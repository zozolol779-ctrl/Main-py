import os
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from openai import OpenAI
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

class EmbeddingService:
    def __init__(self, db: Session):
        self.db = db
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
        self.client = OpenAI(api_key=self.api_key) if self.api_key else None

    async def get_embedding(self, text: str) -> List[float]:
        """Generate embedding vector for text."""
        if not self.client:
            logger.warning("OPENAI_API_KEY not set. Returning zero vector.")
            return [0.0] * 1536
        
        try:
            response = self.client.embeddings.create(
                input=text,
                model=self.model
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return [0.0] * 1536

    async def store_fact(
        self, 
        source_type: str, 
        source_id: str, 
        content: str, 
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Store a semantic fact in the database."""
        vector = await self.get_embedding(content)
        
        # SQL with pgvector cast
        sql = text("""
            INSERT INTO embeddings (source_type, source_id, text, embedding, metadata, created_at)
            VALUES (:type, :id, :text, :vector::vector, :meta, :ts)
            ON CONFLICT (source_type, source_id, md5(text)) DO NOTHING
        """)
        
        try:
            self.db.execute(sql, {
                "type": source_type,
                "id": str(source_id),
                "text": content,
                "vector": str(vector), # PostGIS/pgvector often takes string literal [1,2,3]
                "meta": json.dumps(metadata or {}),
                "ts": datetime.utcnow()
            })
            self.db.commit()
        except Exception as e:
            logger.error(f"Error storing embedding: {e}")
            self.db.rollback()

    async def retrieve_similar(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Find most semantically similar facts."""
        query_vector = await self.get_embedding(query)
        
        # Using cosine distance operator <#>
        sql = text("""
            SELECT source_type, source_id, text, metadata, (embedding <#> :vector::vector) * -1 AS similarity
            FROM embeddings
            ORDER BY embedding <#> :vector::vector
            LIMIT :k
        """)
        
        try:
            result = self.db.execute(sql, {
                "vector": str(query_vector),
                "k": top_k
            }).mappings().all()
            return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Error retrieving similar facts: {e}")
            return []
