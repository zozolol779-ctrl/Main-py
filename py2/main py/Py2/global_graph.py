from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from core.database import get_db
from core.schemas import GraphDataResponse, GraphNode, GraphLink
from core.graph_db import graph_db

router = APIRouter(prefix="/graph", tags=["Global Graph"])

@router.get("/data", response_model=GraphDataResponse)
def get_global_graph_data(
    db: Session = Depends(get_db)
):
    """Get all graph data from Neo4j for the global Command Center view"""
    cypher = """
    MATCH (n)-[r]->(m) 
    RETURN n, r, m 
    ORDER BY n.value 
    LIMIT 150
    """
    try:
        results = graph_db.query(cypher)
    except Exception as e:
        # Fallback to empty graph if Neo4j is down
        return GraphDataResponse(nodes=[], links=[])
    
    nodes_map = {}
    links = []
    
    for record in results:
        source_node = record['n']
        target_node = record['m']
        rel = record['r']
        
        for n in [source_node, target_node]:
            # Neo4j node IDs or use 'value' as unique key
            n_id = n.get('value', str(n.id))
            if n_id not in nodes_map:
                label = n.get('label', n_id)
                n_type = list(n.labels)[0] if n.labels else "Entity"
                
                # Semantic coloring/sizing
                val = 15 if n_type == "Target" else 10 if n_type == "Service" else 5
                
                nodes_map[n_id] = {
                    "id": n_id,
                    "name": label,
                    "group": n_type.lower(),
                    "val": val
                }
        
        links.append({
            "source": source_node.get('value', str(source_node.id)),
            "target": target_node.get('value', str(target_node.id)),
            "type": rel.type
        })
    
    # Format for react-force-graph-3d
    return {
        "nodes": list(nodes_map.values()),
        "links": links
    }
