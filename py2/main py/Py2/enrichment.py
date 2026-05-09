"""
Enrichment Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Dict, Any
from core.database import get_db
from core.schemas import EntityEnrichmentResponse
from core.security import get_current_user
from models.models import Investigation, Entity, EntityEnrichment, EntityType
from services.enrichment import VirusTotalEnricher, AbuseIPDBEnricher, GeoIPEnricher, WhoisEnricher
import json
from datetime import datetime, timezone

router = APIRouter(prefix="/investigations/{investigation_id}/enrichment", tags=["enrichment"])

# Initialize enrichers
vt_enricher = VirusTotalEnricher()
abuseipdb_enricher = AbuseIPDBEnricher()
geoip_enricher = GeoIPEnricher()
whois_enricher = WhoisEnricher()

@router.post("/entities/{entity_id}/virustotal")
def enrich_entity_virustotal(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Enrich entity with VirusTotal data"""
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
    
    # Call appropriate VirusTotal method based on entity type
    result = {}
    
    if entity.type == EntityType.file_hash:
        result = vt_enricher.check_hash(entity.value)
    elif entity.type == EntityType.url:
        result = vt_enricher.check_url(entity.value)
    elif entity.type == EntityType.domain:
        result = vt_enricher.check_domain(entity.value)
    elif entity.type == EntityType.ip_address:
        result = vt_enricher.check_ip(entity.value)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"VirusTotal enrichment not supported for {entity.type}"
        )
    
    # Save enrichment to database
    if "error" not in result:
        enrichment = EntityEnrichment(
            entity_id=entity_id,
            source="VirusTotal",
            enrichment_type=entity.type.value,
            value=json.dumps(result),
            confidence=0.9
        )
        db.add(enrichment)
        db.commit()
    
    return result

@router.post("/entities/{entity_id}/abuseipdb")
def enrich_entity_abuseipdb(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Enrich entity with AbuseIPDB reputation data"""
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
    
    if entity.type != EntityType.ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AbuseIPDB enrichment only supports IP addresses"
        )
    
    result = abuseipdb_enricher.check_ip(entity.value)
    
    # Save enrichment to database
    if "error" not in result:
        enrichment = EntityEnrichment(
            entity_id=entity_id,
            source="AbuseIPDB",
            enrichment_type="reputation",
            value=json.dumps(result),
            confidence=0.85
        )
        db.add(enrichment)
        db.commit()
    
    return result

@router.post("/entities/{entity_id}/geoip")
def enrich_entity_geoip(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Enrich entity with GeoIP location data"""
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
    
    if entity.type == EntityType.ip_address:
        result = geoip_enricher.get_location(entity.value)
    elif entity.type == EntityType.domain:
        # Could resolve domain and then get geolocation
        result = {"error": "For domains, resolve to IP first"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GeoIP enrichment only supports IP addresses"
        )
    
    # Save enrichment to database
    if "error" not in result:
        enrichment = EntityEnrichment(
            entity_id=entity_id,
            source="GeoIP",
            enrichment_type="location",
            value=json.dumps(result),
            confidence=0.95
        )
        db.add(enrichment)
        db.commit()
    
    return result

@router.post("/entities/{entity_id}/whois")
def enrich_entity_whois(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Enrich entity with WHOIS data"""
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
    
    result = {}
    
    if entity.type == EntityType.domain:
        result = whois_enricher.get_domain_whois(entity.value)
    elif entity.type == EntityType.ip_address:
        result = whois_enricher.get_ip_whois(entity.value)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WHOIS enrichment only supports domains and IPs"
        )
    
    # Save enrichment to database
    if "error" not in result:
        enrichment = EntityEnrichment(
            entity_id=entity_id,
            source="WHOIS",
            enrichment_type="registration",
            value=json.dumps(result),
            confidence=0.9
        )
        db.add(enrichment)
        db.commit()
    
    return result

@router.post("/entities/{entity_id}/all")
def enrich_entity_all(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Run all available enrichment services on entity"""
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
    
    results = {}
    
    # Try VirusTotal
    if entity.type in [EntityType.file_hash, EntityType.url, EntityType.domain, EntityType.ip_address]:
        results["virustotal"] = vt_enricher.check_hash(entity.value) if entity.type == EntityType.file_hash else \
                                vt_enricher.check_url(entity.value) if entity.type == EntityType.url else \
                                vt_enricher.check_domain(entity.value) if entity.type == EntityType.domain else \
                                vt_enricher.check_ip(entity.value)
    
    # Try AbuseIPDB for IPs
    if entity.type == EntityType.ip_address:
        results["abuseipdb"] = abuseipdb_enricher.check_ip(entity.value)
        results["geoip"] = geoip_enricher.get_location(entity.value)
    
    # Try WHOIS
    if entity.type in [EntityType.domain, EntityType.ip_address]:
        results["whois"] = whois_enricher.get_domain_whois(entity.value) if entity.type == EntityType.domain else \
                          whois_enricher.get_ip_whois(entity.value)
    
    return results

@router.get("/entities/{entity_id}", response_model=list[EntityEnrichmentResponse])
def get_entity_enrichments(
    investigation_id: int,
    entity_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all enrichment data for entity"""
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
    
    enrichments = db.query(EntityEnrichment).filter(
        EntityEnrichment.entity_id == entity_id
    ).all()
    
    return enrichments
