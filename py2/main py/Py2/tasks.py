"""
Celery Tasks for Background Processing
"""
from celery import Celery, shared_task
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize Celery
celery_app = Celery(
    "spiderai",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379")
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes hard limit
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
)

@shared_task(bind=True)
def enrich_entity_batch(self, investigation_id: int, entity_ids: list):
    """
    Batch enrich entities in background
    """
    from core.database import SessionLocal
    from models.models import Entity
    from services.enrichment import VirusTotalEnricher, AbuseIPDBEnricher, GeoIPEnricher
    
    db = SessionLocal()
    vt = VirusTotalEnricher()
    abuseipdb = AbuseIPDBEnricher()
    geoip = GeoIPEnricher()
    
    try:
        for i, entity_id in enumerate(entity_ids):
            # Update task progress
            self.update_state(
                state='PROGRESS',
                meta={'current': i + 1, 'total': len(entity_ids)}
            )
            
            entity = db.query(Entity).filter(Entity.id == entity_id).first()
            if entity:
                # Enrich based on type
                if entity.type.value == "ip_address":
                    abuseipdb.check_ip(entity.value)
                    geoip.get_location(entity.value)
                elif entity.type.value == "file_hash":
                    vt.check_hash(entity.value)
                elif entity.type.value == "domain":
                    vt.check_domain(entity.value)
                elif entity.type.value == "url":
                    vt.check_url(entity.value)
        
        return {'status': 'complete', 'total': len(entity_ids)}
    
    finally:
        db.close()

@shared_task(bind=True)
def analyze_pcap_file(self, investigation_id: int, file_path: str):
    """
    Analyze PCAP file in background
    """
    from ingestion import IngestionEngine
    
    try:
        ingestion = IngestionEngine()
        result = ingestion.process_file(file_path)
        
        return {
            'status': 'complete',
            'investigation_id': investigation_id,
            'result': result
        }
    
    except Exception as e:
        raise self.retry(exc=e, countdown=60)

@shared_task
def correlate_entities_task(investigation_id: int):
    """
    Correlate entities and compute relationship weights
    """
    from core.database import SessionLocal
    from models.models import Investigation, EntityRelationship
    import math
    
    db = SessionLocal()
    
    try:
        investigation = db.query(Investigation).filter(
            Investigation.id == investigation_id
        ).first()
        
        if not investigation:
            return {'error': 'Investigation not found'}
        
        # Get all relationships
        relationships = db.query(EntityRelationship).filter(
            EntityRelationship.investigation_id == investigation_id
        ).all()
        
        updated = 0
        for rel in relationships:
            count = rel.cooccurrence_count
            
            # Base weight formula
            base_weight = min(1.0, math.log(1 + count) / math.log(1 + 50))
            
            # Apply boosts
            boost = 0.0
            if rel.metadata:
                # Could parse metadata for temporal proximity
                boost += 0.1
            
            final_weight = min(1.0, base_weight + boost)
            rel.weight = final_weight
            updated += 1
        
        db.commit()
        return {'status': 'complete', 'relationships_updated': updated}
    
    finally:
        db.close()

@shared_task
def generate_intelligence_report(investigation_id: int):
    """
    Generate comprehensive intelligence report
    """
    from core.database import SessionLocal
    from models.models import Investigation
    from reporter import Reporter
    
    db = SessionLocal()
    
    try:
        investigation = db.query(Investigation).filter(
            Investigation.id == investigation_id
        ).first()
        
        if not investigation:
            return {'error': 'Investigation not found'}
        
        # Generate report
        reporter = Reporter(output_dir="static/reports")
        report_path = reporter.generate_reports(
            graph=investigation,
            timeline=[],
            threats=[],
            profiles=[]
        )
        
        return {
            'status': 'complete',
            'report_path': report_path,
            'investigation_id': investigation_id
        }
    
    finally:
        db.close()

@shared_task
def monitor_threat_indicators(investigation_id: int):
    """
    Monitor threat indicators for changes
    """
    from core.database import SessionLocal
    from models.models import Investigation, ThreatIndicator
    
    db = SessionLocal()
    
    try:
        investigation = db.query(Investigation).filter(
            Investigation.id == investigation_id
        ).first()
        
        if not investigation:
            return {'error': 'Investigation not found'}
        
        threats = db.query(ThreatIndicator).filter(
            ThreatIndicator.investigation_id == investigation_id
        ).all()
        
        high_severity = sum(1 for t in threats if t.severity.value == "high")
        critical_severity = sum(1 for t in threats if t.severity.value == "critical")
        
        return {
            'status': 'monitored',
            'total_threats': len(threats),
            'high_severity': high_severity,
            'critical_severity': critical_severity
        }
    
    finally:
        db.close()
