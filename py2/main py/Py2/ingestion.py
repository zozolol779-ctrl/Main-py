import logging
from core.graph_db import graph_db
from typing import Dict, Any

logger = logging.getLogger(__name__)

class IngestionService:
    def __init__(self):
        pass

    def ingest_data(self, data: Dict[str, Any], investigation_id: str):
        """
        Ingest a single data item (Flow or DNS) into Neo4j.
        """
        try:
            if data["type"] == "TRAFFIC_FLOW":
                self._ingest_flow(data, investigation_id)
            elif data["type"] == "DNS_QUERY":
                self._ingest_dns_query(data, investigation_id)
            elif data["type"] == "DNS_RESOLUTION":
                self._ingest_dns_resolution(data, investigation_id)
            elif data["type"] == "CREDENTIAL_EXPOSED":
                self._ingest_credential(data, investigation_id)
        except Exception as e:
            logger.error(f"Error ingesting data: {e}")

    def _ingest_flow(self, data: Dict[str, Any], investigation_id: str):
        query = """
        MERGE (src:IP {value: $source})
        MERGE (dst:IP {value: $target})
        MERGE (src)-[r:COMMUNICATED_WITH {investigation_id: $inv_id}]->(dst)
        ON CREATE SET r.first_seen = $timestamp, r.count = 1, r.protocol = $protocol, r.size = $size
        ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1, r.size = r.size + $size
        """
        params = {
            "source": data["source"],
            "target": data["target"],
            "inv_id": investigation_id,
            "timestamp": data["timestamp"],
            "protocol": data.get("protocol", 0),
            "size": data.get("size", 0)
        }
        graph_db.execute_query(query, params)

    def _ingest_dns_query(self, data: Dict[str, Any], investigation_id: str):
        query = """
        MERGE (src:IP {value: $source})
        MERGE (domain:Domain {value: $target})
        MERGE (src)-[r:QUERIED_DNS {investigation_id: $inv_id}]->(domain)
        ON CREATE SET r.timestamp = $timestamp
        """
        params = {
            "source": data["source"],
            "target": data["target"],
            "inv_id": investigation_id,
            "timestamp": data["timestamp"]
        }
        graph_db.execute_query(query, params)

    def _ingest_dns_resolution(self, data: Dict[str, Any], investigation_id: str):
        query = """
        MERGE (domain:Domain {value: $source})
        MERGE (ip:IP {value: $target})
        MERGE (domain)-[r:RESOLVED_TO {investigation_id: $inv_id}]->(ip)
        ON CREATE SET r.timestamp = $timestamp
        """
        params = {
            "source": data["source"], # Domain
            "target": data["target"], # IP
            "inv_id": investigation_id,
            "timestamp": data["timestamp"]
        }
        graph_db.execute_query(query, params)

    def _ingest_credential(self, data: Dict[str, Any], investigation_id: str):
        """
        Ingest exposed credentials. High Severity Event.
        """
        query = """
        MERGE (src:IP {value: $source})
        MERGE (dst:IP {value: $target})
        MERGE (cred:Credential {value: $value})
        ON CREATE SET cred.type = $cred_type, cred.captured_at = $timestamp
        
        MERGE (src)-[r:LEAKED_CREDENTIAL {investigation_id: $inv_id}]->(cred)
        MERGE (cred)-[r2:EXPOSED_ON]->(dst)
        """
        params = {
            "source": data["source"],
            "target": data["target"],
            "value": data["value"],
            "cred_type": data["cred_type"],
            "inv_id": investigation_id,
            "timestamp": data["timestamp"]
        }
        graph_db.execute_query(query, params)

# Global Instance
ingestion_service = IngestionService()
