import math
import networkx as nx

class EntityCorrelator:
    def __init__(self):
        pass

    def correlate_and_score(self, graph: nx.DiGraph):
        """
        Iterates over all edges and computes the weight.
        """
        for u, v, data in graph.edges(data=True):
            count = data.get("count", 1)
            
            # Base Weight Formula: min(1.0, log(1 + count) / log(1 + 50))
            base_weight = min(1.0, math.log(1 + count) / math.log(1 + 50))
            
            # Boosters
            boost = 0.0
            
            # +0.2 if same domain or certificate (simplified check)
            # We need to check node properties.
            node_u = graph.nodes[u]
            node_v = graph.nodes[v]
            
            # Example: If both are part of the same "Cluster"
            # This requires cluster info to be back-propagated to nodes.
            
            # +0.3 if temporal proximity <= 60s (requires analyzing raw events behind the edge)
            # For MVP, we assume 'temporal_proximity' flag is set by Extractor if detected.
            if data.get("temporal_proximity"):
                boost += 0.3

            final_weight = min(1.0, base_weight + boost)
            
            # Update edge
            graph[u][v]["weight"] = round(final_weight, 2)
            graph[u][v]["label"] = f"{data.get('type')} (w={final_weight:.2f})"
