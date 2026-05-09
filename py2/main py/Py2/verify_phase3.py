import sys
import os
# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.graph_db import graph_db
from services.forensics.ingestion import ingestion_service
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_credential_ingestion():
    try:
        logger.info("Testing Credential Ingestion...")
        
        # Simulate a credential leak extracted by Scapy
        dummy_cred = {
            "type": "CREDENTIAL_EXPOSED",
            "source": "192.168.1.50",
            "target": "10.0.0.99",
            "cred_type": "FTP_PLAINTEXT",
            "value": "USER admin PASS s3cr3t",
            "timestamp": datetime.now().isoformat()
        }
        
        ingestion_service.ingest_data(dummy_cred, "test_investigation_PHASE3")
        
        # Verify in Neo4j
        logger.info("Verifying in Neo4j...")
        query = """
        MATCH (src:IP {value: '192.168.1.50'})-[r:LEAKED_CREDENTIAL]->(c:Credential) 
        RETURN c.value as val
        """
        result = graph_db.execute_query(query)
        
        if result and result[0]['val'] == "USER admin PASS s3cr3t":
            logger.info(f"✅ FOUND CREDENTIAL IN DB: {result[0]['val']}")
            return True
        else:
            logger.error("❌ Credential NOT found in DB!")
            return False
            
    except Exception as e:
        logger.error(f"Ingestion Logic Failed: {e}")
        return False

if __name__ == "__main__":
    print("-" * 50)
    print("PHASE 3: BRAIN TRANSPLANT VERIFICATION")
    print("-" * 50)
    
    # Ensure DB connection
    graph_db.connect()
    
    if test_credential_ingestion():
        print("\n✅ SUCCESS: The system can now hunt and store stolen credentials!")
    else:
        print("\n❌ FAILURE: Something went wrong.")
