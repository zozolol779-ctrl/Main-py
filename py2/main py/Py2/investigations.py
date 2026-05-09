"""
Investigation Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import os
import shutil
import tempfile
from core.database import get_db
from core.schemas import InvestigationCreate, InvestigationUpdate, InvestigationResponse
from core.security import get_current_user
from models.models import Investigation, User
from services.forensics.extractor import ScapyDeepExtractor
from services.forensics.ingestion import ingestion_service

# Initialize Extractor
extractor = ScapyDeepExtractor()

router = APIRouter(prefix="/investigations", tags=["investigations"])

@router.post("", response_model=InvestigationResponse)
def create_investigation(
    investigation: InvestigationCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new investigation"""
    db_investigation = Investigation(
        title=investigation.title,
        description=investigation.description,
        created_by=current_user.user_id
    )
    db.add(db_investigation)
    db.commit()
    db.refresh(db_investigation)
    return db_investigation

@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List all investigations for current user"""
    investigations = db.query(Investigation).filter(
        Investigation.created_by == current_user.user_id
    ).offset(skip).limit(limit).all()
    return investigations

@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get investigation by ID"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    return investigation

@router.put("/{investigation_id}", response_model=InvestigationResponse)
def update_investigation(
    investigation_id: int,
    investigation_update: InvestigationUpdate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update investigation"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    if investigation_update.title:
        investigation.title = investigation_update.title
    if investigation_update.description:
        investigation.description = investigation_update.description
    
    db.commit()
    db.refresh(investigation)
    return investigation

@router.delete("/{investigation_id}")
def delete_investigation(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete investigation"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    db.delete(investigation)
    db.commit()
    db.delete(investigation)
    db.commit()
    return {"message": "Investigation deleted"}

def process_pcap_background(file_path: str, investigation_id: int):
    """Background task to process PCAP"""
    try:
        print(f"🕵️ Starting background forensic analysis for ID: {investigation_id}")
        
        # 1. Extract
        for item in extractor.extract_from_pcap(file_path):
            # 2. Ingest
            ingestion_service.ingest_data(item, str(investigation_id))
            
        print(f"✅ Forensic analysis complete for ID: {investigation_id}")
    except Exception as e:
        print(f"❌ Error during forensic analysis: {e}")
    finally:
        # Cleanup temp file
        if os.path.exists(file_path):
            os.remove(file_path)

@router.post("/{investigation_id}/upload")
async def upload_pcap(
    investigation_id: int,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload PCAP for deep forensic analysis"""
    # Verify ownership
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Save to temp file
    try:
        suffix = f".{file.filename.split('.')[-1]}" if '.' in file.filename else ".pcap"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(file.file, tmp)
            temp_path = tmp.name
        
        # Dispatch background task
        background_tasks.add_task(process_pcap_background, temp_path, investigation_id)
        
        return {"message": "File uploaded. Forensic analysis started in background.", "filename": file.filename}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
