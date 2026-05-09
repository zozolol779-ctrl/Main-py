"""
ML Models for Threat Intelligence
- Threat Classification
- Behavioral Analysis
- Link Prediction
"""
import os
import json
import pickle
import logging
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pandas as pd

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """
    ML Model for threat classification
    Classifies entities/IPs/Domains as: benign, suspicious, malicious
    """
    
    MODEL_PATH = "models/threat_classifier.pkl"
    SCALER_PATH = "models/threat_scaler.pkl"
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model from disk"""
        try:
            if os.path.exists(self.MODEL_PATH) and os.path.exists(self.SCALER_PATH):
                with open(self.MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                logger.info("✅ Threat classifier model loaded")
            else:
                logger.info("ℹ️ No pre-trained model found, will use default")
                self._create_default_model()
        except Exception as e:
            logger.error(f"Error loading threat classifier: {e}")
            self._create_default_model()
    
    def _create_default_model(self):
        """Create and train default model with dummy data"""
        # Default model - train on synthetic data
        X_train, y_train = self._generate_training_data(1000)
        self.train(X_train, y_train)
    
    def _generate_training_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data"""
        X = np.random.rand(n_samples, 10)  # 10 features
        
        # Generate labels based on feature patterns
        y = np.zeros(n_samples)
        for i in range(n_samples):
            score = np.sum(X[i][:5])  # Use first 5 features
            if score > 3:
                y[i] = 2  # Malicious
            elif score > 1.5:
                y[i] = 1  # Suspicious
            else:
                y[i] = 0  # Benign
        
        return X, y
    
    def extract_features(self, entity_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from entity data
        Features: age, reputation_score, connections_count, etc.
        """
        features = []
        
        # 1. Age (days since first seen)
        first_seen = entity_data.get("first_seen")
        age_days = 0
        if first_seen:
            from datetime import datetime
            age_days = (datetime.now() - datetime.fromisoformat(first_seen)).days
        features.append(min(age_days / 365, 1.0))  # Normalize to 0-1
        
        # 2. Reputation score (0-100)
        reputation = entity_data.get("reputation_score", 50) / 100
        features.append(reputation)
        
        # 3. Connections count (log scale)
        connections = entity_data.get("connections_count", 0)
        features.append(np.log1p(connections) / 10)  # Log scale
        
        # 4. Enrichment hits count
        enrichment_hits = len(entity_data.get("enrichment_data", {}))
        features.append(enrichment_hits / 10)
        
        # 5. Threat indicators count
        threat_indicators = len(entity_data.get("threat_indicators", []))
        features.append(threat_indicators / 20)
        
        # 6. Unique ports (for IPs)
        unique_ports = len(set(entity_data.get("ports", [])))
        features.append(unique_ports / 100)
        
        # 7. Open ports ratio
        open_ports = entity_data.get("open_ports_count", 0)
        total_ports = entity_data.get("scanned_ports", 1)
        features.append(open_ports / total_ports if total_ports > 0 else 0)
        
        # 8. Geo IP distance from known targets
        geo_distance = entity_data.get("geo_distance_to_targets", 1000)
        features.append(min(geo_distance / 10000, 1.0))
        
        # 9. ASN reputation (if available)
        asn_reputation = entity_data.get("asn_reputation", 50) / 100
        features.append(asn_reputation)
        
        # 10. Active connections count (recent activity)
        active_connections = entity_data.get("active_connections", 0)
        features.append(active_connections / 100)
        
        return np.array(features).reshape(1, -1)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """Train the threat classifier model"""
        try:
            # Normalize features
            X_scaled = self.scaler.fit_transform(X_train)
            
            # Train Random Forest
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_scaled, y_train)
            self.is_trained = True
            
            # Save model
            os.makedirs("models", exist_ok=True)
            with open(self.MODEL_PATH, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.SCALER_PATH, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info("✅ Threat classifier model trained and saved")
        
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
    
    def predict(self, entity_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict threat classification for entity
        Returns: classification (0=benign, 1=suspicious, 2=malicious), confidence
        """
        if not self.is_trained:
            return {"error": "Model not trained"}
        
        try:
            features = self.extract_features(entity_data)
            features_scaled = self.scaler.transform(features)
            
            # Prediction
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            classification_map = {0: "benign", 1: "suspicious", 2: "malicious"}
            
            return {
                "classification": classification_map[prediction],
                "confidence": float(probabilities[int(prediction)]),
                "probabilities": {
                    "benign": float(probabilities[0]),
                    "suspicious": float(probabilities[1]),
                    "malicious": float(probabilities[2])
                }
            }
        
        except Exception as e:
            logger.error(f"Error predicting threat classification: {e}")
            return {"error": str(e)}


class BehavioralAnalyzer:
    """
    ML Model for behavioral analysis
    Detects anomalies in entity behavior
    """
    
    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False
    
    def extract_behavioral_features(self, timeline_events: List[Dict]) -> np.ndarray:
        """Extract behavioral features from timeline events"""
        if not timeline_events:
            return np.zeros((1, 5))
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(timeline_events)
        
        features = []
        
        # 1. Event frequency (events per hour)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_span_hours = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600
            event_frequency = len(df) / max(time_span_hours, 1)
            features.append(event_frequency)
        else:
            features.append(0)
        
        # 2. Unique event types ratio
        unique_types = df['event_type'].nunique() if 'event_type' in df.columns else 1
        type_diversity = unique_types / max(len(df), 1)
        features.append(type_diversity)
        
        # 3. Burst detection (high activity in short time)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df_sorted = df.sort_values('timestamp')
            time_diffs = df_sorted['timestamp'].diff().dt.total_seconds()
            burst_score = 1.0 if (time_diffs < 10).sum() > len(df) * 0.3 else 0.0
            features.append(burst_score)
        else:
            features.append(0)
        
        # 4. Location diversity (if available)
        locations = df['source'].nunique() if 'source' in df.columns else 1
        location_diversity = min(locations / 10, 1.0)
        features.append(location_diversity)
        
        # 5. Severity distribution
        severity_high = (df['severity'] == 'high').sum() if 'severity' in df.columns else 0
        severity_ratio = severity_high / max(len(df), 1)
        features.append(severity_ratio)
        
        return np.array(features).reshape(1, -1)
    
    def train(self, timeline_data: List[Dict]):
        """Train behavioral analyzer on timeline data"""
        try:
            # Extract features from all timelines
            all_features = []
            for timeline in timeline_data:
                features = self.extract_behavioral_features(timeline)
                all_features.append(features[0])
            
            X_train = np.array(all_features)
            if len(X_train) > 0:
                self.model.fit(X_train)
                self.is_trained = True
                logger.info("✅ Behavioral analyzer trained")
            
        except Exception as e:
            logger.error(f"Error training behavioral analyzer: {e}")
    
    def detect_anomaly(self, timeline_events: List[Dict]) -> Dict[str, Any]:
        """Detect anomalies in behavioral timeline"""
        if not self.is_trained:
            # Return neutral if not trained
            return {"anomaly_detected": False, "anomaly_score": 0.5}
        
        try:
            features = self.extract_behavioral_features(timeline_events)
            
            # Isolation Forest prediction (-1 = anomaly, 1 = normal)
            prediction = self.model.predict(features)[0]
            anomaly_score = -self.model.score_samples(features)[0]  # Higher = more anomalous
            
            # Normalize anomaly score to 0-1
            anomaly_score = 1.0 / (1.0 + np.exp(-anomaly_score))
            
            return {
                "anomaly_detected": prediction == -1,
                "anomaly_score": float(anomaly_score),
                "severity": "high" if anomaly_score > 0.7 else "medium" if anomaly_score > 0.4 else "low"
            }
        
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return {"error": str(e)}


class LinkPredictor:
    """
    ML Model for predicting hidden relationships
    Uses graph embeddings and network analysis
    """
    
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
    
    def extract_link_features(self, entity_pair: Tuple[Dict, Dict]) -> np.ndarray:
        """Extract features for link prediction"""
        e1, e2 = entity_pair
        
        features = []
        
        # 1. Type similarity (same type = 1, different = 0)
        type_similarity = 1.0 if e1.get("type") == e2.get("type") else 0.0
        features.append(type_similarity)
        
        # 2. Common connections count
        common_connections = len(set(e1.get("connections", [])) & set(e2.get("connections", [])))
        features.append(min(common_connections / 10, 1.0))
        
        # 3. Temporal proximity (co-occurrence in time)
        t1_start = e1.get("first_seen")
        t1_end = e1.get("last_seen")
        t2_start = e2.get("first_seen")
        t2_end = e2.get("last_seen")
        
        temporal_overlap = 0.0
        if t1_start and t2_start:
            from datetime import datetime
            t1_start = datetime.fromisoformat(t1_start)
            t1_end = datetime.fromisoformat(t1_end or t1_start)
            t2_start = datetime.fromisoformat(t2_start)
            t2_end = datetime.fromisoformat(t2_end or t2_start)
            
            overlap_start = max(t1_start, t2_start)
            overlap_end = min(t1_end, t2_end)
            
            if overlap_start <= overlap_end:
                temporal_overlap = 1.0
        
        features.append(temporal_overlap)
        
        # 4. Geographic proximity (same country/region)
        geo_proximity = 1.0 if e1.get("country") == e2.get("country") else 0.0
        features.append(geo_proximity)
        
        # 5. Reputation similarity (both good or both bad)
        r1 = e1.get("reputation_score", 50)
        r2 = e2.get("reputation_score", 50)
        reputation_similarity = 1.0 - min(abs(r1 - r2) / 100, 1.0)
        features.append(reputation_similarity)
        
        # 6. Threat indicator overlap
        indicators1 = set(e1.get("threat_indicators", []))
        indicators2 = set(e2.get("threat_indicators", []))
        indicator_overlap = len(indicators1 & indicators2) / max(len(indicators1 | indicators2), 1)
        features.append(indicator_overlap)
        
        # 7. ASN similarity (same AS network)
        asn_similarity = 1.0 if e1.get("asn") == e2.get("asn") else 0.0
        features.append(asn_similarity)
        
        # 8. Organization similarity
        org_similarity = 1.0 if e1.get("organization") == e2.get("organization") else 0.0
        features.append(org_similarity)
        
        return np.array(features).reshape(1, -1)
    
    def train(self, entity_pairs: List[Tuple[Dict, Dict]], labels: List[int]):
        """Train link prediction model"""
        try:
            X_train = []
            for pair in entity_pairs:
                features = self.extract_link_features(pair)
                X_train.append(features[0])
            
            X_train = np.array(X_train)
            y_train = np.array(labels)
            
            if len(X_train) > 0:
                self.model.fit(X_train, y_train)
                self.is_trained = True
                logger.info("✅ Link predictor model trained")
        
        except Exception as e:
            logger.error(f"Error training link predictor: {e}")
    
    def predict_link(self, entity_pair: Tuple[Dict, Dict]) -> Dict[str, Any]:
        """Predict if two entities are likely connected"""
        if not self.is_trained:
            return {"error": "Model not trained"}
        
        try:
            features = self.extract_link_features(entity_pair)
            
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            return {
                "connected": bool(prediction),
                "confidence": float(probabilities[int(prediction)]),
                "probability": float(probabilities[1])
            }
        
        except Exception as e:
            logger.error(f"Error predicting link: {e}")
            return {"error": str(e)}
