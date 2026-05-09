import logging
from typing import List, Dict, Any
import networkx as nx

logger = logging.getLogger(__name__)

class PersonProfiler:
    def __init__(self):
        self.profiles = {} # Key: Person ID (e.g., email), Value: Profile Data

    def build_profiles(self, entities: Dict[str, List[str]], graph: nx.DiGraph) -> List[Dict]:
        """
        Scans for human identifiers and builds person-centric graphs.
        """
        human_identifiers = []
        
        # 1. Detect Human Identifiers
        for email in entities.get("emails", []):
            human_identifiers.append({"type": "Email", "value": email})
        
        for phone in entities.get("phones", []):
            human_identifiers.append({"type": "Phone", "value": phone})
            
        # Check for names in WHOIS or Certs (if available in graph properties)
        # This requires iterating the graph nodes
        for node, data in graph.nodes(data=True):
            if data.get("type") == "Person":
                human_identifiers.append({"type": "Person", "value": data.get("label")})

        if not human_identifiers:
            logger.info("No human identifiers found. Skipping Person Intelligence phase.")
            return []

        logger.info(f"Triggered Person Intelligence for {len(human_identifiers)} identities.")
        
        # 2. Build Relationships
        profiles = []
        for identity in human_identifiers:
            profile = {
                "identity": identity,
                "related_infrastructure": [],
                "role_probability": {"Operator": 0.0, "Victim": 0.0, "Broker": 0.0}
            }
            
            # Find connected nodes in the graph (BFS/DFS limited depth)
            # For this MVP, we look for direct edges or 1-hop
            # We need to find the node ID corresponding to this identity value
            # This is a bit tricky if we don't have a direct map. 
            # Let's assume the graph has nodes with 'label' == identity value.
            
            target_node_id = None
            for n, d in graph.nodes(data=True):
                if d.get("label") == identity["value"]:
                    target_node_id = n
                    break
            
            if target_node_id:
                # Analyze neighbors
                neighbors = list(graph.neighbors(target_node_id))
                for neighbor in neighbors:
                    n_data = graph.nodes[neighbor]
                    profile["related_infrastructure"].append({
                        "id": neighbor,
                        "type": n_data.get("type"),
                        "label": n_data.get("label")
                    })
                    
                # 3. Assign Role Probabilities (Heuristics)
                self._calculate_role(profile, graph)
            
            profiles.append(profile)
            
        return profiles

    def _calculate_role(self, profile, graph):
        """
        Estimates if the person is an Attacker (Operator), Victim, or Infrastructure Broker.
        """
        identity = profile["identity"]
        related = profile["related_infrastructure"]
        
        score_operator = 0.0
        score_victim = 0.0
        
        # Heuristic 1: Connected to C2 or Malware?
        # We need to check if related nodes are flagged as threats.
        # This requires passing threat data or checking node properties.
        
        for item in related:
            # Check if node has 'threat_severity' property
            node_data = graph.nodes[item["id"]]
            if node_data.get("threat_severity") in ["High", "Critical"]:
                # If an email is registered to a C2 domain -> Operator
                score_operator += 0.8
            
            if item["type"] == "Leak":
                # If email appears in a leak -> Victim (usually)
                score_victim += 0.6

        # Heuristic 2: Email Domain
        email = identity["value"]
        if "@" in email:
            domain = email.split("@")[1]
            if domain in ["protonmail.com", "tutanota.com", "cock.li"]:
                score_operator += 0.3 # Suspicious privacy providers
            elif domain in ["corp.com", "company.com"]: # Corporate email
                score_victim += 0.2

        # Normalize
        total = score_operator + score_victim + 0.01
        profile["role_probability"]["Operator"] = round(score_operator / total, 2)
        profile["role_probability"]["Victim"] = round(score_victim / total, 2)
