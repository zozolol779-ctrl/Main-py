from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from core.database import get_db
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
from datetime import datetime
from agents.hunter_core import HunterAgent
from models.models import Investigation

router = APIRouter(prefix="/agents", tags=["Autonomous Agents"])

class InvestigationRequest(BaseModel):
    target: str
    context: Optional[str] = "Autonomous threat hunt"
    agent_id: str = "hunter-v1"

class InvestigationResponse(BaseModel):
    status: str
    message: str
    job_id: str

@router.post("/investigate", response_model=InvestigationResponse)
@router.post("/initiate_hunt", response_model=InvestigationResponse)
async def start_investigation(
    request: InvestigationRequest, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Start an autonomous investigation.
    Creates a persistent Investigation record as the 'Job'.
    """
    # 1. Create the persistent record (acting as our Job)
    db_investigation = Investigation(
        title=f"Hunt: {request.target}",
        description=f"Autonomous investigation of {request.target}. Context: {request.context}",
        status="running",
        created_by=1, # Default to system/analyst user for now
        agent_logs="[]"
    )
    db.add(db_investigation)
    db.commit()
    db.refresh(db_investigation)
    
    job_id = str(db_investigation.id)
    
    # 2. Dispatch the actual agent work to background
    background_tasks.add_task(run_agent_task, job_id, request.target, request.context)
    
    return {
        "status": "queued",
        "message": f"Investigation started for {request.target}",
        "job_id": job_id
    }

@router.get("/jobs")
async def list_jobs(db: Session = Depends(get_db)):
    """List all agent-related investigations."""
    hunts = db.query(Investigation).filter(Investigation.title.like("Hunt: %")).order_by(Investigation.created_at.desc()).all()
    return [
        {
            "job_id": str(h.id),
            "target": h.title.replace("Hunt: ", ""),
            "status": h.status,
            "created_at": h.created_at
        } for h in hunts
    ]

@router.get("/stream/{job_id}")
async def stream_job(job_id: str):
    """Placeholder for SSE streaming. For now, frontend should fallback to polling."""
    raise HTTPException(status_code=501, detail="Streaming not implemented. Use polling on /jobs/{job_id}")

@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Retrieve the status and logs of a specific hunt."""
    try:
        inv_id = int(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format")

    investigation = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Parse logs from JSON string
    try:
        logs = json.loads(investigation.agent_logs or "[]")
    except:
        logs = []

    return {
        "job_id": job_id,
        "status": investigation.status,
        "target": investigation.title.replace("Hunt: ", ""),
        "logs": logs
    }

async def run_agent_task(job_id: str, target: str, context: str):
    """
    Background worker that runs the Hunter Agent and periodically flushes 
    logs to the database.
    """
    # We need a new DB session for the background task
    from core.database import SessionLocal
    db = SessionLocal()
    
    try:
        inv_id = int(job_id)
        agent = HunterAgent(agent_id="hunter-v1", db=db)
        
        # We wrap the agent run to capture intermediate steps if possible, 
        # but for now we'll just wait for complete results as per hunter_core design.
        result = await agent.run_investigation(target, context)
        
        # Format steps as logs
        formatted_logs = [
            {
                "id": f"{job_id}-{s['step']}",
                "type": "thought" if s.get("thought") else "action",
                "content": s.get("thought") or s.get("action"),
                "ts": s.get("timestamp")
            }
            for s in result.get("steps", [])
        ]
        
        # Update DB
        investigation = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if investigation:
            investigation.status = "completed"
            investigation.agent_logs = json.dumps(formatted_logs)
            db.commit()
            
    except Exception as e:
        print(f"Agent Task Error: {e}")
        db.rollback()
        investigation = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if investigation:
            investigation.status = "failed"
            db.commit()
    finally:
        db.close()
