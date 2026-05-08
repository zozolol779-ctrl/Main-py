from neo4j import GraphDatabase
import os
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

class Neo4jDriver:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "spider_graph_pass")
        self.driver = None

    def connect(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.verify_connectivity()
            logger.info("Connected to Neo4j successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise

    def verify_connectivity(self):
        self.driver.verify_connectivity()

    def close(self):
        if self.driver:
            self.driver.close()

    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.driver:
            self.connect()
        
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Alias for execute_query to maintain interface consistency."""
        return self.execute_query(query, parameters)

# Global instance
graph_db = Neo4jDriver()
