"""
Threat Indicators Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db
from core.schemas import ThreatIndicatorCreate, ThreatIndicatorResponse
from core.security import get_current_user
from models.models import Investigation, ThreatIndicator

router = APIRouter(prefix="/investigations/{investigation_id}/threats", tags=["threats"])

@router.post("", response_model=ThreatIndicatorResponse)
def create_threat_indicator(
    investigation_id: int,
    threat: ThreatIndicatorCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create threat indicator"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    db_threat = ThreatIndicator(
        investigation_id=investigation_id,
        indicator_type=threat.indicator_type,
        indicator_value=threat.indicator_value,
        severity=threat.severity,
        description=threat.description,
        confidence=threat.confidence,
        metadata=str(threat.metadata) if threat.metadata else None
    )
    
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    return db_threat

@router.get("", response_model=List[ThreatIndicatorResponse])
def list_threat_indicators(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List threat indicators"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    threats = db.query(ThreatIndicator).filter(
        ThreatIndicator.investigation_id == investigation_id
    ).offset(skip).limit(limit).all()
    
    return threats

@router.get("/{threat_id}", response_model=ThreatIndicatorResponse)
def get_threat_indicator(
    investigation_id: int,
    threat_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get threat indicator"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    threat = db.query(ThreatIndicator).filter(
        ThreatIndicator.id == threat_id,
        ThreatIndicator.investigation_id == investigation_id
    ).first()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found"
        )
    
    return threat

@router.delete("/{threat_id}")
def delete_threat_indicator(
    investigation_id: int,
    threat_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete threat indicator"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    threat = db.query(ThreatIndicator).filter(
        ThreatIndicator.id == threat_id,
        ThreatIndicator.investigation_id == investigation_id
    ).first()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found"
        )
    
    db.delete(threat)
    db.commit()
    return {"message": "Threat indicator deleted"}
