"""
Machine Learning Routes
- Threat Classification
- Behavioral Analysis
- Link Prediction
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.database import get_db
from core.security import require_role
from models.models import User, Entity, EntityRelationship
from services.ml_models import ThreatClassifier, BehavioralAnalyzer, LinkPredictor
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["machine-learning"])

threat_classifier = ThreatClassifier()
behavioral_analyzer = BehavioralAnalyzer()
link_predictor = LinkPredictor()


@router.post("/threat-classification/classify")
async def classify_threat(
    entity_data: Dict[str, Any],
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Classify entity as benign, suspicious, or malicious using ML"""
    
    if not entity_data:
        raise HTTPException(status_code=400, detail="Entity data required")
    
    result = threat_classifier.predict(entity_data)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "model": "threat_classifier",
        "classification": result
    }


@router.post("/threat-classification/batch")
async def classify_threat_batch(
    entities: List[Dict[str, Any]],
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Classify multiple entities"""
    
    if not entities:
        raise HTTPException(status_code=400, detail="Entities required")
    
    results = []
    for entity in entities:
        result = threat_classifier.predict(entity)
        results.append({
            "entity_id": entity.get("id"),
            "classification": result
        })
    
    return {
        "model": "threat_classifier",
        "total": len(results),
        "results": results
    }


@router.post("/threat-classification/train")
async def train_threat_classifier(
    training_data: Dict[str, Any],
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """Train threat classifier with new data"""
    
    import numpy as np
    
    X_train = np.array(training_data.get("features", []))
    y_train = np.array(training_data.get("labels", []))
    
    if len(X_train) == 0 or len(y_train) == 0:
        raise HTTPException(status_code=400, detail="Training data required")
    
    threat_classifier.train(X_train, y_train)
    
    return {
        "status": "trained",
        "samples": len(X_train),
        "model": "threat_classifier"
    }


@router.post("/behavioral-analysis/detect-anomaly")
async def detect_behavioral_anomaly(
    timeline_events: List[Dict[str, Any]],
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Detect anomalies in entity behavioral timeline"""
    
    if not timeline_events:
        raise HTTPException(status_code=400, detail="Timeline events required")
    
    result = behavioral_analyzer.detect_anomaly(timeline_events)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "model": "behavioral_analyzer",
        "anomaly_analysis": result
    }


@router.post("/behavioral-analysis/batch")
async def detect_behavioral_anomalies_batch(
    investigation_id: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Detect anomalies for all entities in investigation"""
    
    from models.models import TimelineEvent
    
    # Get all timeline events for investigation
    events = db.query(TimelineEvent).filter(
        TimelineEvent.investigation_id == investigation_id
    ).all()
    
    if not events:
        raise HTTPException(status_code=404, detail="No timeline events found")
    
    # Group by entity
    entity_timelines = {}
    for event in events:
        if event.entity_id not in entity_timelines:
            entity_timelines[event.entity_id] = []
        entity_timelines[event.entity_id].append(event.to_dict())
    
    results = []
    for entity_id, timeline in entity_timelines.items():
        anomaly = behavioral_analyzer.detect_anomaly(timeline)
        results.append({
            "entity_id": entity_id,
            "anomaly_analysis": anomaly
        })
    
    return {
        "model": "behavioral_analyzer",
        "investigation_id": investigation_id,
        "total_entities": len(results),
        "results": results
    }


@router.post("/behavioral-analysis/train")
async def train_behavioral_analyzer(
    timeline_data: List[List[Dict[str, Any]]],
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """Train behavioral analyzer with timeline data"""
    
    if not timeline_data:
        raise HTTPException(status_code=400, detail="Timeline data required")
    
    behavioral_analyzer.train(timeline_data)
    
    return {
        "status": "trained",
        "timelines": len(timeline_data),
        "model": "behavioral_analyzer"
    }


@router.post("/link-prediction/predict")
async def predict_link(
    entity_pair: Dict[str, Any],
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Predict if two entities are likely connected"""
    
    if "entity1" not in entity_pair or "entity2" not in entity_pair:
        raise HTTPException(status_code=400, detail="Two entities required")
    
    result = link_predictor.predict_link((entity_pair["entity1"], entity_pair["entity2"]))
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "model": "link_predictor",
        "prediction": result
    }


@router.post("/link-prediction/batch")
async def predict_links_batch(
    entity_pairs: List[Dict[str, Any]],
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Predict links for multiple entity pairs"""
    
    if not entity_pairs:
        raise HTTPException(status_code=400, detail="Entity pairs required")
    
    results = []
    for pair in entity_pairs:
        if "entity1" not in pair or "entity2" not in pair:
            continue
        
        result = link_predictor.predict_link((pair["entity1"], pair["entity2"]))
        results.append({
            "entity1_id": pair.get("entity1_id"),
            "entity2_id": pair.get("entity2_id"),
            "prediction": result
        })
    
    return {
        "model": "link_predictor",
        "total_pairs": len(results),
        "results": results
    }


@router.post("/link-prediction/investigation")
async def predict_links_investigation(
    investigation_id: str,
    min_confidence: float = 0.6,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Predict hidden links for all entities in investigation"""
    
    # Get all entities in investigation
    entities = db.query(Entity).filter(
        Entity.investigation_id == investigation_id
    ).all()
    
    if len(entities) < 2:
        raise HTTPException(status_code=400, detail="At least 2 entities required")
    
    # Predict links for all pairs
    results = []
    for i in range(len(entities)):
        for j in range(i + 1, len(entities)):
            entity1_data = entities[i].to_dict()
            entity2_data = entities[j].to_dict()
            
            prediction = link_predictor.predict_link((entity1_data, entity2_data))
            
            if "error" not in prediction and prediction.get("probability", 0) >= min_confidence:
                results.append({
                    "entity1_id": entities[i].id,
                    "entity1_value": entities[i].value,
                    "entity2_id": entities[j].id,
                    "entity2_value": entities[j].value,
                    "connected": prediction.get("connected"),
                    "confidence": prediction.get("confidence")
                })
    
    # Sort by confidence
    results.sort(key=lambda x: x["confidence"], reverse=True)
    
    return {
        "model": "link_predictor",
        "investigation_id": investigation_id,
        "total_entities": len(entities),
        "predicted_links": len(results),
        "results": results[:50]  # Top 50
    }


@router.post("/link-prediction/train")
async def train_link_predictor(
    entity_pairs: List[Dict[str, Any]],
    labels: List[int],
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """Train link prediction model"""
    
    if len(entity_pairs) != len(labels):
        raise HTTPException(status_code=400, detail="Pairs and labels must match in length")
    
    if len(entity_pairs) < 10:
        raise HTTPException(status_code=400, detail="At least 10 training samples required")
    
    # Extract entity data from pairs
    pairs_with_data = []
    for pair in entity_pairs:
        pairs_with_data.append((pair.get("entity1"), pair.get("entity2")))
    
    link_predictor.train(pairs_with_data, labels)
    
    return {
        "status": "trained",
        "samples": len(pairs_with_data),
        "model": "link_predictor"
    }


@router.get("/models/status")
async def models_status(
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get status of all ML models"""
    
    return {
        "threat_classifier": {
            "trained": threat_classifier.is_trained,
            "model_type": "Random Forest",
            "features": 10,
            "classes": 3
        },
        "behavioral_analyzer": {
            "trained": behavioral_analyzer.is_trained,
            "model_type": "Isolation Forest",
            "features": 5,
            "contamination": 0.1
        },
        "link_predictor": {
            "trained": link_predictor.is_trained,
            "model_type": "Random Forest",
            "features": 8,
            "classes": 2
        }
    }
