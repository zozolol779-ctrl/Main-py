"""
Graph Data Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.database import get_db
from core.schemas import GraphDataResponse, GraphNode, GraphLink
from core.security import get_current_user
from models.models import Investigation, Entity, EntityRelationship
from services.graph_rag import GraphRAGService
from pydantic import BaseModel

router = APIRouter(prefix="/investigations/{investigation_id}/graph", tags=["graph"])

@router.get("", response_model=GraphDataResponse)
def get_graph_data(
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get graph data for visualization"""
    # ... existing code ...
    return GraphDataResponse(nodes=nodes, links=links)

@router.get("/all", response_model=GraphDataResponse)
def get_all_graph_data(
    db: Session = Depends(get_db)
):
    """Get all graph data from Neo4j (Global View)"""
    from core.graph_db import graph_db
    
    cypher = "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100"
    results = graph_db.query(cypher)
    
    nodes_map = {}
    links = []
    
    for record in results:
        source_node = record['n']
        target_node = record['m']
        rel = record['r']
        
        for n in [source_node, target_node]:
            n_id = n.id
            if n_id not in nodes_map:
                nodes_map[n_id] = GraphNode(
                    id=n_id,
                    type=list(n.labels)[0] if n.labels else "Entity",
                    label=n.get('label', n.get('value', 'Unknown')),
                    value=n.get('value', '')
                )
        
        links.append(GraphLink(
            source=source_node.id,
            target=target_node.id,
            relationship_type=rel.type,
            weight=1.0
        ))
    
    return GraphDataResponse(nodes=list(nodes_map.values()), links=links)

class GraphQueryRequest(BaseModel):
    query: str

@router.post("/query/natural")
async def query_graph_natural(
    investigation_id: int,
    request: GraphQueryRequest,
    db: Session = Depends(get_db)
):
    """Execute a natural language query against the graph"""
    service = GraphRAGService(db)
    return await service.query_graph_natural_language(investigation_id, request.query)
