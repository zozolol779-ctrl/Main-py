from typing import Dict, Any, List, Optional
import os
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text
from services.enrichment.shodan import ShodanEnricher
from services.enrichment.greynoise import GreyNoiseEnricher
from services.embeddings import EmbeddingService
from core.graph_db import graph_db

logger = logging.getLogger(__name__)

class ToolRegistry:
    def __init__(self, db: Optional[Session] = None):
        self.db = db
        self.shodan = ShodanEnricher()
        self.greynoise = GreyNoiseEnricher()
        self.embeddings = EmbeddingService(db) if db else None
        self.tools = {
            "enrich_entity": self.enrich_entity,
            "search_logs": self.search_logs,
            "query_graph": self.query_graph,
            "finish_investigation": self.finish_investigation
        }

    async def execute(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.tools:
            return {"error": f"Tool '{tool_name}' not found."}
        
        try:
            # Most tools are synchronous wrappers of async or sync calls
            if tool_name == "enrich_entity":
                result = await self.enrich_entity(**tool_args)
            elif tool_name == "search_logs":
                result = self.search_logs(**tool_args)
            elif tool_name == "query_graph":
                result = self.query_graph(**tool_args)
            else:
                result = await self.tools[tool_name](**tool_args)
            
            return {"status": "success", "data": result}
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {"status": "error", "message": str(e)}

    async def enrich_entity(self, value: str, type: str) -> Dict[str, Any]:
        """Query real external APIs and store in Vector DB for GraphRAG."""
        intel = {"shodan": {}, "greynoise": {}}
        
        if type.lower() == "ip":
            shodan_res = self.shodan.host_lookup(value)
            if "error" not in shodan_res:
                intel["shodan"] = shodan_res
            
            gn_res = self.greynoise.ip_lookup(value)
            if "error" not in gn_res:
                intel["greynoise"] = gn_res

        result = {
            "entity": value,
            "type": type,
            "intel": intel,
            "verdict": "suspicious" if (intel["greynoise"].get("classification") == "malicious") else "unknown"
        }

        # Index for GraphRAG
        if self.embeddings:
            summary = f"Entity: {value} ({type}). Shodan ISP: {intel['shodan'].get('isp', 'N/A')}. GreyNoise: {intel['greynoise'].get('classification', 'N/A')}."
            # Run in background ideally, but for now we await
            await self.embeddings.store_fact(source_type=type, source_id=value, content=summary, metadata=result)

        return result

    def search_logs(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search real PostgreSQL entities/investigations database."""
        if not self.db:
            return [{"error": "Database session not available"}]
            
        sql = text("""
            SELECT e.value, e.type, e.label, e.confidence, i.title as investigation
            FROM entities e
            LEFT JOIN investigation_entities ie ON e.id = ie.entity_id
            LEFT JOIN investigations i ON ie.investigation_id = i.id
            WHERE e.value LIKE :query OR e.label LIKE :query
            LIMIT :limit
        """)
        
        try:
            result = self.db.execute(sql, {"query": f"%{query}%", "limit": limit}).mappings().all()
            return [dict(row) for row in result]
        except Exception as e:
            return [{"error": f"Database query failed: {str(e)}"}]

    def query_graph(self, value: str) -> Dict[str, Any]:
        """Query real Neo4j graph for neighbors and relationships."""
        try:
            cypher = """
            MATCH (n {value: $value})-[r]-(m)
            RETURN n.value as source, type(r) as relationship, m.value as target, labels(m) as target_labels
            LIMIT 20
            """
            results = graph_db.query(cypher, {"value": value})
            return {
                "entity": value,
                "connections": results,
                "count": len(results)
            }
        except Exception as e:
            return {"error": f"Neo4j query failed: {str(e)}"}

    async def finish_investigation(self, verdict: str, summary: str) -> Dict[str, Any]:
        """Finalize the investigation."""
        return {
            "final_verdict": verdict,
            "final_summary": summary,
            "action": "COMPLETED",
            "timestamp": "2025-12-21T05:20:00"
        }
