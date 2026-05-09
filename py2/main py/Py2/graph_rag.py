from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from core.database import get_db
from services.embeddings import EmbeddingService
from core.graph_db import graph_db
from openai import OpenAI
import os
import json

router = APIRouter(prefix="/graph", tags=["GraphRAG"])

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

class QueryReq(BaseModel):
    question: str
    top_k: int = 6
    hops: int = 2

@router.post("/query/natural")
async def graph_query_natural(
    req: QueryReq,
    db: Session = Depends(get_db)
):
    """
    Execute a GraphRAG query:
    1. Retrieve similar facts from pgvector.
    2. Fetch subgraphs from Neo4j for relevant entities.
    3. Generate an AI answer using the combined context.
    """
    if not client:
        return {"answer": "AI Engine restricted: OPENAI_API_KEY missing.", "provenance": []}

    # 1. Retrieve similar facts from vector DB
    emb_svc = EmbeddingService(db)
    facts = await emb_svc.retrieve_similar(req.question, top_k=req.top_k)
    
    if not facts:
        return {"answer": "No relevant data found in current intelligence.", "provenance": []}

    snippets = [f["text"] for f in facts]
    
    # 2. Fetch subgraphs from Neo4j
    # We take the most relevant entity IDs from the facts to pivot our graph search
    entity_ids = list(set([f["source_id"] for f in facts if f["source_type"] in ["IP", "Target", "Host"]]))
    
    graph_context = ""
    subgraph_data = {"nodes": [], "links": []}
    
    if entity_ids:
        # Safe APOC subgraph call with limit
        cypher = """
        MATCH (n) WHERE n.value IN $ids
        CALL apoc.path.subgraphAll(n, {maxLevel: $hops, limit: 100})
        YIELD nodes, relationships
        RETURN 
            [node in nodes | {id: id(node), value: node.value, label: node.label, labels: labels(node)}] as nodes,
            [rel in relationships | {
                id: id(rel), 
                type: type(rel), 
                start_node_value: startNode(rel).value, 
                end_node_value: endNode(rel).value
            }] as relationships
        """
        try:
            results = graph_db.query(cypher, {"ids": entity_ids, "hops": req.hops})
            if results:
                record = results[0]
                nodes = record.get('nodes', [])
                rels = record.get('relationships', [])
                
                # Serialize for UI - ensure we handle dicts from record.data()
                subgraph_data = {
                    "nodes": [
                        {
                            "id": n.get('value', str(n.get('id', 'unknown'))), 
                            "name": n.get('label', n.get('value', 'Unknown')), 
                            "group": (n.get('labels', ['Entity'])[0]).lower(),
                            "val": 15 if "Target" in n.get('labels', []) else 5
                        } for n in nodes
                    ],
                    "links": [
                        {
                            "source": r.get('start_node_value', 'unknown'), 
                            "target": r.get('end_node_value', 'unknown'), 
                            "type": r.get('type', 'RELATES_TO')
                        } for r in rels
                    ]
                }
                
                # Context for LLM
                node_summaries = [f"{n.get('value', 'Unknown')} ({','.join(n.get('labels', ['Entity']))})" for n in nodes[:20]]
                graph_context = "Connections found: " + ", ".join(node_summaries)
        except Exception as e:
            graph_context = f"Graph engine busy: {str(e)}"

    # 3. Generate LLM Answer
    prompt = f"""
    You are 'Antigravity AI', a specialized Cyber Threat Intelligence assistant.
    The user is asking a question about their monitored network.
    
    CRITICAL INSTRUCTIONS:
    - Base your answer ONLY on the provided context snippets and graph connections.
    - If evidence is insufficient, state "INSUFFICIENT_EVIDENCE" and suggest what data to collect.
    - List every NODE ID (IPs/Names) used as evidence.
    - Keep it focused and professional.

    QUESTION: {req.question}

    CONTEXT SNIPPETS (Semantic Search):
    {chr(10).join([f"- {s}" for s in snippets])}

    NETWORK TOPOLOGY CONTEXT (Graph):
    {graph_context}
    """
    
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a professional Cyber Intelligence Assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0
        )
        answer = response.choices[0].message.content
    except Exception as e:
        answer = f"Error generating intelligence summary: {str(e)}"

    return {
        "answer": answer,
        "provenance": [{"source_id": f["source_id"], "text": f["text"]} for f in facts],
        "subgraph": subgraph_data
    }
