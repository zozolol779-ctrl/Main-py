"""
Red King C2 — Backend entrypoint.

CRITICAL LOAD ORDER:
  1. os, pathlib, dotenv   (stdlib + dotenv)
  2. load_dotenv()          ← must fire before any from app.core import
  3. Everything else

Reason: app.core.database.SovereignDB reads NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD
via os.getenv() inside __init__, which runs the moment the module is first imported.
If load_dotenv() fires after that import the env vars are never seen.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env before any app.core import ─────────────────────────────────────
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)
sys.stderr.write("✅ .env loaded\n")
sys.stderr.flush()
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import json
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List

from fastapi import Body, FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# app.core imports — safe after load_dotenv()
from app.core.database import sovereign_db
from app.core.swarm_manager import SwarmManager
from app.core.achievements import AchievementEngine
from app.core.advisor import StrategicAdvisor
from app.core.redirector import RedirectorManager
from app.core.llm_commander import hive_mind
from app.core.logger import logger

# Optional: scapy-based forensics (may be unavailable on Windows without Npcap)
try:
    from app.core.pcap_forensics import PcapWarlord
    _pcap_available = True
except Exception as _pcap_err:
    _pcap_available = False
    logger.warning(f"[-] PCAP forensics unavailable: {_pcap_err}")

# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(title="Red King C2", version="2.1.0-WarRoom")

# ── CORS ──────────────────────────────────────────────────────────────────────
_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5555")
_origins: List[str] = [o.strip() for o in _raw.split(",") if o.strip()]
if os.getenv("ALLOW_ALL_ORIGINS", "false").lower() in ("1", "true", "yes"):
    _origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info(f"[+] CORS allow_origins: {_origins}")

# ── Module-level state ────────────────────────────────────────────────────────
_pending_commands: Dict[str, List[Any]] = {}

_swarm      = SwarmManager(sovereign_db, _pending_commands)
_ach_engine = AchievementEngine(sovereign_db)
_advisor    = StrategicAdvisor(sovereign_db)
_redir      = RedirectorManager(sovereign_db)

# In-memory intel log (ring-buffer, capped at 200 entries)
_intel_log: List[Dict] = [
    {
        "id":  "EVT-BOOT",
        "ts":  datetime.utcnow().isoformat(),
        "type": "SYSTEM",
        "msg": "War Room Online — Sovereign Hive Initialised",
    }
]
_MAX_INTEL = 200

# Active WebSocket connections
_ws_pool: List[WebSocket] = []


# ── Helpers ───────────────────────────────────────────────────────────────────
def _ts() -> str:
    return datetime.utcnow().isoformat()


def _log_intel(type_: str, msg: str) -> None:
    _intel_log.append({"id": str(uuid.uuid4())[:8], "ts": _ts(), "type": type_, "msg": msg})
    if len(_intel_log) > _MAX_INTEL:
        del _intel_log[0]


# ══════════════════════════════════════════════════════════════════════════════
#  API ROUTES
#  ALL @app decorators MUST appear before the app.mount() calls below.
#  Registering StaticFiles first causes it to intercept every unmatched
#  /api/* path and return index.html (HTTP 200 text/html), silently breaking
#  every frontend JSON poll.
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health_check():
    return {"status": "OPERATIONAL", "module": "WAR_ROOM_DASHBOARD"}


@app.get("/api/status")
async def get_status():
    agents = sovereign_db.get_agents()   # returns dict
    now = datetime.utcnow()
    active = 0
    for a in agents.values():
        try:
            delta = (now - datetime.fromisoformat(a.get("last_seen", "2000-01-01T00:00:00"))).total_seconds()
            if delta < 120:
                active += 1
        except ValueError:
            pass
    return {
        "system":       "OPERATIONAL",
        "hive_mind":    "ONLINE" if hive_mind.model else "OFFLINE",
        "active_nodes": active,
        "total_agents": len(agents),
    }


@app.get("/api/intel")
async def get_intel():
    return _intel_log[-50:]


@app.get("/api/agents")
async def get_agents():
    # sovereign_db.get_agents() returns a dict; frontend expects a list
    return list(sovereign_db.get_agents().values())


@app.get("/api/dna_map")
async def get_dna_map():
    """
    Returns network nodes discovered via agent scans.
    Shape required by IntelFeed.tsx: [{file, ip, dna}]
    """
    nodes = sovereign_db.db.get("nodes", {})
    return [
        {
            "file": nid,
            "ip":   data.get("ip", nid),
            "dna":  f"MAC:{data.get('mac', 'UNKNOWN')} SEEN:{data.get('last_seen', 'UNKNOWN')}",
        }
        for nid, data in nodes.items()
    ]


# ── SAFETY BOUNDARY ──────────────────────────────────────────────────────────
# ghost_recon: no live HTTP probe is performed.
# Returns a simulation-safe response so IntelFeed renders without crashing.
@app.post("/api/ghost_recon")
async def ghost_recon(payload: Dict = Body(default=None)):
    payload = payload or {}
    ip = payload.get("ip", "UNKNOWN")
    _log_intel("RECON", f"Ghost recon queued for {ip} — dashboard simulation mode")
    return {
        "status": "SUCCESS",
        "title":  f"[SIMULATION] {ip} — live probe disabled in dashboard mode",
        "ip":     ip,
    }


@app.post("/api/ai_assessment")
async def ai_assessment(payload: Dict = Body(default=None)):
    payload = payload or {}
    dna   = payload.get("dna",   "")
    title = payload.get("title", "")
    return await hive_mind.analyze_target(dna, title)


@app.get("/api/graph")
async def get_graph():
    return sovereign_db.get_graph()


@app.get("/api/swarm/stats")
async def get_swarm_stats():
    return _swarm.get_swarm_stats()


@app.post("/api/swarm/execute")
async def swarm_execute(payload: Dict = Body(default=None)):
    payload  = payload or {}
    command  = payload.get("command", {})
    filters  = payload.get("filters", {})
    targeted = _swarm.dispatch_command(command, filters)
    _ach_engine.evaluate()
    _log_intel("SWARM", f"Swarm execute: {targeted} agents targeted")
    return {"targeted_agents": targeted, "status": "QUEUED"}


@app.get("/api/swarm/jobs")
async def get_swarm_jobs():
    return _swarm.get_jobs()


@app.get("/api/achievements")
async def get_achievements():
    _ach_engine.evaluate()
    return _ach_engine.get_all_status()


@app.get("/api/stealth/redirectors")
async def get_redirectors():
    return _redir.get_all_redirectors()


@app.post("/api/stealth/redirectors/register")
async def register_redirector(payload: Dict = Body(default=None)):
    payload  = payload or {}
    ip       = payload.get("ip", "")
    hostname = payload.get("hostname", "")
    rtype    = payload.get("type", "HTTP")
    if not ip or not hostname:
        return JSONResponse({"error": "ip and hostname are required"}, status_code=400)
    rid = _redir.register_redirector(ip, hostname, rtype)
    _log_intel("STEALTH", f"Redirector registered: {hostname} ({ip})")
    return {"status": "REGISTERED", "id": rid}


@app.post("/api/stealth/redirectors/burn")
async def burn_redirector(payload: Dict = Body(default=None)):
    payload = payload or {}
    rid     = payload.get("id")
    if not rid:
        return JSONResponse({"error": "id is required"}, status_code=400)
    _redir.burn_redirector(rid)
    _log_intel("STEALTH", f"Redirector {rid} burned")
    return {"status": "BURNED", "id": rid}


@app.get("/api/strategy/analyze")
async def strategy_analyze():
    return await _advisor.analyze_battlefield()


@app.post("/api/consult")
async def consult(payload: Dict = Body(default=None)):
    payload = payload or {}
    query   = payload.get("query", "")
    if not query:
        return JSONResponse({"error": "query is required"}, status_code=400)
    response = await hive_mind.get_strategic_advice(query)
    _log_intel("AI", f"Consult: {query[:60]}")
    return {"response": response}


# ── SAFETY BOUNDARY ──────────────────────────────────────────────────────────
# /api/hive/queue: stores the command metadata and returns a job_id.
# No command is executed on any system. The _pending_commands dict is consumed
# only by the /api/hive/checkin route which returns queued jobs to checking-in
# agents — the agents themselves decide whether to act on them.
@app.post("/api/hive/queue")
async def hive_queue(payload: Dict = Body(default=None)):
    payload  = payload or {}
    agent_id = payload.get("agent_id", "BROADCAST")
    command  = payload.get("command", "")
    job_id   = f"JOB_{str(uuid.uuid4())[:6].upper()}"
    if agent_id not in _pending_commands:
        _pending_commands[agent_id] = []
    _pending_commands[agent_id].append({"job_id": job_id, "command": command})
    _log_intel("QUEUE", f"Queued for {agent_id}: {str(command)[:40]}")
    return {"status": "QUEUED", "job_id": job_id}


@app.post("/api/hive/checkin")
async def hive_checkin(payload: Dict = Body(default=None)):
    payload  = payload or {}
    agent_id = payload.get("agent_id", f"AGENT_{str(uuid.uuid4())[:6].upper()}")
    data = {
        "id":        agent_id,
        "ip":        payload.get("ip",   "0.0.0.0"),
        "os":        payload.get("os",   "UNKNOWN"),
        "status":    "ACTIVE",
        "user":      payload.get("user", "UNKNOWN"),
        "last_seen": _ts(),
    }
    sovereign_db.upsert_agent(agent_id, data)
    _ach_engine.evaluate()
    _log_intel("CHECKIN", f"Agent {agent_id} checked in from {data['ip']}")
    pending = _pending_commands.pop(agent_id, [])
    return {"status": "ACKNOWLEDGED", "agent_id": agent_id, "commands": pending}


# ── SAFETY BOUNDARY ──────────────────────────────────────────────────────────
# /api/scan: returns known agents from the local database.
# No live network scanning is performed.
@app.post("/api/scan")
async def scan():
    agents = sovereign_db.get_agents()
    details = [
        f"Agent {a.get('id','?')} @ {a.get('ip','?')} [{a.get('os','?')}]"
        for a in agents.values()
    ]
    _log_intel("SCAN", f"Scan simulation — {len(agents)} known agents returned")
    return {"targets_found": len(agents), "details": details}


@app.post("/api/forensics/upload")
async def forensics_upload(file: UploadFile = File(...)):
    if not _pcap_available:
        return JSONResponse(
            status_code=503,
            content={"error": "PCAP analysis not available — scapy/Npcap not installed"},
        )
    suffix   = Path(file.filename or "upload.pcap").suffix or ".pcap"
    tmp_path = Path(tempfile.mktemp(suffix=suffix))
    try:
        with tmp_path.open("wb") as buf:
            shutil.copyfileobj(file.file, buf)
        warlord = PcapWarlord()
        report  = warlord.analyze_pcap(str(tmp_path))
        _log_intel("FORENSICS", f"PCAP analysed: {file.filename} — {report.get('device_count', 0)} devices")
        return {"report": report}
    except Exception as exc:
        logger.error(f"[!] Forensics upload failed: {exc}")
        return JSONResponse(status_code=500, content={"error": str(exc)})
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


# ── INTENTIONALLY DISABLED ────────────────────────────────────────────────────
# /api/war/resurrect would inject extracted session tokens into a browser proxy
# to hijack authenticated sessions on third-party systems — unauthorized access.
# This endpoint is permanently non-operational in this deployment.
@app.post("/api/war/resurrect")
async def war_resurrect():
    return JSONResponse(
        status_code=403,
        content={
            "error":  "DISABLED",
            "reason": "Session resurrection is non-operational in this deployment.",
        },
    )


# Legacy alias kept for backward compatibility
@app.post("/api/analyze-pcap")
async def analyze_pcap_legacy(file: UploadFile = File(...)):
    return await forensics_upload(file)


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/api/hive/stream/{agent_id}")
async def hive_stream(websocket: WebSocket, agent_id: str):
    await websocket.accept()
    _ws_pool.append(websocket)
    logger.info(f"[WS] Connected: {agent_id}")
    try:
        while True:
            await websocket.send_json({
                "type":     "HEARTBEAT",
                "agent_id": agent_id,
                "ts":       _ts(),
                "intel":    _intel_log[-5:],
            })
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        logger.info(f"[WS] Disconnected: {agent_id}")
    except Exception as exc:
        logger.error(f"[WS] Error for {agent_id}: {exc}")
    finally:
        if websocket in _ws_pool:
            _ws_pool.remove(websocket)


# ══════════════════════════════════════════════════════════════════════════════
#  Static / SPA mount — MUST be the last thing registered.
#
#  If app.mount("/", ...) is registered before the @app.* route decorators,
#  FastAPI will match every unknown /api/* path against the StaticFiles handler
#  first and serve index.html with HTTP 200 text/html — silencing all 404s
#  and breaking every frontend JSON parser.
# ══════════════════════════════════════════════════════════════════════════════
_BASE_DIR      = Path(__file__).resolve().parent
_FRONTEND_DIST = (_BASE_DIR.parent / "war_room" / "dist").resolve()

_assets = _FRONTEND_DIST / "assets"
if _assets.exists():
    app.mount("/assets", StaticFiles(directory=str(_assets)), name="assets")

if _FRONTEND_DIST.exists():
    logger.info(f"[+] Serving frontend from: {_FRONTEND_DIST}")
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="spa")
else:
    logger.warning(f"[-] Frontend dist not found at {_FRONTEND_DIST}. Run: cd war_room && npm run build")

    @app.get("/{catchall:path}")
    async def spa_fallback(catchall: str):
        return JSONResponse(
            status_code=503,
            content={
                "error": "Frontend not built",
                "hint":  "cd Red_King_C2/war_room && npm run build",
            },
        )


# ── Dev entrypoint ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=9001, reload=True)
