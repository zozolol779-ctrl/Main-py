"""
Timeline Events Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db
from core.schemas import TimelineEventCreate, TimelineEventResponse
from core.security import get_current_user
from models.models import Investigation, TimelineEvent

router = APIRouter(prefix="/investigations/{investigation_id}/timeline", tags=["timeline"])

@router.post("", response_model=TimelineEventResponse)
def create_timeline_event(
    investigation_id: int,
    event: TimelineEventCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create timeline event"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    db_event = TimelineEvent(
        investigation_id=investigation_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        summary=event.summary,
        description=event.description,
        source_entity_id=event.source_entity_id,
        target_entity_id=event.target_entity_id,
        metadata=str(event.metadata) if event.metadata else None
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event

@router.get("", response_model=List[TimelineEventResponse])
def list_timeline_events(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 1000
):
    """List timeline events sorted by timestamp"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    events = db.query(TimelineEvent).filter(
        TimelineEvent.investigation_id == investigation_id
    ).order_by(TimelineEvent.timestamp).offset(skip).limit(limit).all()
    
    return events

@router.get("/{event_id}", response_model=TimelineEventResponse)
def get_timeline_event(
    investigation_id: int,
    event_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get timeline event"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    event = db.query(TimelineEvent).filter(
        TimelineEvent.id == event_id,
        TimelineEvent.investigation_id == investigation_id
    ).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Timeline event not found"
        )
    
    return event

@router.delete("/{event_id}")
def delete_timeline_event(
    investigation_id: int,
    event_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete timeline event"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    event = db.query(TimelineEvent).filter(
        TimelineEvent.id == event_id,
        TimelineEvent.investigation_id == investigation_id
    ).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Timeline event not found"
        )
    
    db.delete(event)
    db.commit()
    return {"message": "Timeline event deleted"}
