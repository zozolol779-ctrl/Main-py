"""
Entity Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db
from core.schemas import EntityCreate, EntityUpdate, EntityResponse
from core.security import get_current_user
from models.models import Entity, Investigation

router = APIRouter(prefix="/investigations/{investigation_id}/entities", tags=["entities"])

@router.post("", response_model=EntityResponse)
def create_entity(
    investigation_id: int,
    entity: EntityCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new entity in investigation"""
    # Verify investigation ownership
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check if entity already exists
    existing_entity = db.query(Entity).filter(Entity.value == entity.value).first()
    
    if existing_entity:
        # Add to investigation if not already there
        if investigation not in existing_entity.investigations:
            existing_entity.investigations.append(investigation)
        db.commit()
        db.refresh(existing_entity)
        return existing_entity
    
    # Create new entity
    db_entity = Entity(
        type=entity.type,
        value=entity.value,
        label=entity.label or entity.value,
        description=entity.description,
        confidence=entity.confidence,
        metadata=str(entity.metadata) if entity.metadata else None
    )
    db_entity.investigations.append(investigation)
    db.add(db_entity)
    db.commit()
    db.refresh(db_entity)
    return db_entity

@router.get("", response_model=List[EntityResponse])
def list_entities(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List entities in investigation"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    entities = db.query(Entity).join(
        Entity.investigations
    ).filter(
        Investigation.id == investigation_id
    ).offset(skip).limit(limit).all()
    
    return entities

@router.get("/{entity_id}", response_model=EntityResponse)
def get_entity(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get entity by ID"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    entity = db.query(Entity).filter(
        Entity.id == entity_id
    ).first()
    
    if not entity or investigation not in entity.investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entity not found"
        )
    
    return entity

@router.put("/{entity_id}", response_model=EntityResponse)
def update_entity(
    investigation_id: int,
    entity_id: int,
    entity_update: EntityUpdate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update entity"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    
    if not entity or investigation not in entity.investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entity not found"
        )
    
    if entity_update.label:
        entity.label = entity_update.label
    if entity_update.description:
        entity.description = entity_update.description
    if entity_update.confidence:
        entity.confidence = entity_update.confidence
    if entity_update.metadata:
        entity.metadata = str(entity_update.metadata)
    
    db.commit()
    db.refresh(entity)
    return entity

@router.delete("/{entity_id}")
def delete_entity(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete entity from investigation"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    
    if not entity or investigation not in entity.investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entity not found"
        )
    
    entity.investigations.remove(investigation)
    db.commit()
    return {"message": "Entity removed from investigation"}
