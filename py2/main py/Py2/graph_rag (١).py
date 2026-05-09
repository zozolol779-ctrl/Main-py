from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any, List
import json
import random

class GraphRAGService:
    def __init__(self, db: Session):
        self.db = db

    async def query_graph_natural_language(self, investigation_id: int, query: str) -> Dict[str, Any]:
        """
        Convert natural language query to SQL/Graph query and execute it.
        """
        # 1. Convert Natural Language to SQL (Mocking LLM here)
        sql_query = self._mock_llm_nl_to_sql(query, investigation_id)
        
        # 2. Execute Query
        try:
            result = self.db.execute(text(sql_query)).mappings().all()
            data = [dict(row) for row in result]
            
            # 3. Summarize Result (Mocking LLM here)
            summary = self._mock_llm_summarize(query, data)
            
            return {
                "query": query,
                "generated_sql": sql_query,
                "data": data,
                "summary": summary
            }
        except Exception as e:
            return {
                "error": str(e),
                "generated_sql": sql_query
            }

    def _mock_llm_nl_to_sql(self, query: str, investigation_id: int) -> str:
        """
        Mock LLM that translates NL to SQL.
        In production, this would call OpenAI/Anthropic.
        """
        # Simple keyword matching for demo purposes
        if "bad" in query.lower() or "suspicious" in query.lower():
            # "Find suspicious IPs" -> Select entities with 'suspicious' reputation or high threat score
            return f"""
                SELECT e.value, e.label, e.type 
                FROM entities e 
                JOIN investigation_entities ie ON e.id = ie.entity_id 
                WHERE ie.investigation_id = {investigation_id} 
                AND (e.label LIKE '%malicious%' OR e.confidence < 0.5)
                LIMIT 5
            """
        elif "connect" in query.lower() or "talk" in query.lower():
            # "Who is connecting to X?" -> Join relationships
            return f"""
                SELECT s.value as source, r.relationship_type, t.value as target 
                FROM entity_relationships r
                JOIN entities s ON r.source_id = s.id
                JOIN entities t ON r.target_id = t.id
                WHERE r.investigation_id = {investigation_id}
                LIMIT 10
            """
        else:
            # Default: list entities
            return f"""
                SELECT value, type, label 
                FROM entities e 
                JOIN investigation_entities ie ON e.id = ie.entity_id
                WHERE ie.investigation_id = {investigation_id}
                LIMIT 5
            """

    def _mock_llm_summarize(self, query: str, data: List[Dict[str, Any]]) -> str:
        if not data:
            return "No results found matching your query."
        
        count = len(data)
        if "source" in data[0]:
            return f"I found {count} connections. Key activity involves {data[0]['source']} communicating with {data[0]['target']}."
        return f"I found {count} relevant entities, including {data[0].get('value')}."
