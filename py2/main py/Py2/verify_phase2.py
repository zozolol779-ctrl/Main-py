import sys
import os
# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.graph_db import graph_db
from services.forensics.extractor import ScapyDeepExtractor
from services.forensics.ingestion import ingestion_service
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_neo4j_connection():
    try:
        logger.info("Testing Neo4j Connection...")
        graph_db.connect()
        # Run a simple query
        result = graph_db.execute_query("RETURN 'Hello Neo4j' as msg")
        logger.info(f"Neo4j Response: {result[0]['msg']}")
        return True
    except Exception as e:
        logger.error(f"Neo4j Connection Failed: {e}")
        return False

def test_ingestion_logic():
    try:
        logger.info("Testing Ingestion Logic...")
        dummy_data = {
            "type": "TRAFFIC_FLOW",
            "source": "1.1.1.1",
            "target": "8.8.8.8",
            "protocol": 6,
            "size": 128,
            "timestamp": "2023-01-01T12:00:00"
        }
        ingestion_service.ingest_data(dummy_data, "test_investigation_001")
        logger.info("Ingestion function executed without error.")
        return True
    except Exception as e:
        logger.error(f"Ingestion Logic Failed: {e}")
        return False

if __name__ == "__main__":
    print("-" * 50)
    print("PHASE 2 VERIFICATION")
    print("-" * 50)
    
    neo4j_ok = test_neo4j_connection()
    ingestion_ok = test_ingestion_logic()
    
    if neo4j_ok and ingestion_ok:
        print("\n✅ SUCCESS: Phase 2 Engine is READY!")
    else:
        print("\n❌ FAILURE: Check logs above.")
