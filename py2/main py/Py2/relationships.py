"""
Entity Relationship Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db
from core.schemas import EntityRelationshipCreate, EntityRelationshipResponse
from core.security import get_current_user
from models.models import EntityRelationship, Investigation, Entity

router = APIRouter(prefix="/investigations/{investigation_id}/relationships", tags=["relationships"])

@router.post("", response_model=EntityRelationshipResponse)
def create_relationship(
    investigation_id: int,
    relationship: EntityRelationshipCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create relationship between entities"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Verify entities exist and belong to investigation
    source = db.query(Entity).filter(Entity.id == relationship.source_id).first()
    target = db.query(Entity).filter(Entity.id == relationship.target_id).first()
    
    if not source or investigation not in source.investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source entity not found in investigation"
        )
    
    if not target or investigation not in target.investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target entity not found in investigation"
        )
    
    # Create relationship
    db_relationship = EntityRelationship(
        investigation_id=investigation_id,
        source_id=relationship.source_id,
        target_id=relationship.target_id,
        relationship_type=relationship.relationship_type,
        weight=relationship.weight,
        confidence=relationship.confidence,
        metadata=str(relationship.metadata) if relationship.metadata else None
    )
    
    db.add(db_relationship)
    db.commit()
    db.refresh(db_relationship)
    return db_relationship

@router.get("", response_model=List[EntityRelationshipResponse])
def list_relationships(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List all relationships in investigation"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    relationships = db.query(EntityRelationship).filter(
        EntityRelationship.investigation_id == investigation_id
    ).offset(skip).limit(limit).all()
    
    return relationships

@router.get("/{relationship_id}", response_model=EntityRelationshipResponse)
def get_relationship(
    investigation_id: int,
    relationship_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get relationship by ID"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    relationship = db.query(EntityRelationship).filter(
        EntityRelationship.id == relationship_id,
        EntityRelationship.investigation_id == investigation_id
    ).first()
    
    if not relationship:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Relationship not found"
        )
    
    return relationship

@router.delete("/{relationship_id}")
def delete_relationship(
    investigation_id: int,
    relationship_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete relationship"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    relationship = db.query(EntityRelationship).filter(
        EntityRelationship.id == relationship_id,
        EntityRelationship.investigation_id == investigation_id
    ).first()
    
    if not relationship:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Relationship not found"
        )
    
    db.delete(relationship)
    db.commit()
    return {"message": "Relationship deleted"}
