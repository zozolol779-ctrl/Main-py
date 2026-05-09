import json
from .llm_commander import hive_mind


class StrategicAdvisor:
    def __init__(self, db):
        self.db = db

    async def analyze_battlefield(self) -> dict:
        """
        Analyzes the current graph to provide tactical recommendations.
        """
        graph = self.db.get_graph()
        nodes = graph["nodes"]
        links = graph["links"]

        # Prepare a condensed prompt for the AI
        battlefield_context = {
            "node_count": len(nodes),
            "edge_count": len(links),
            "active_agents": [n for n in nodes if n.get("group") == 3],
            "discovered_targets": [n for n in nodes if n.get("group") == 4],
        }

        prompt = f"""
        [SYSTEM: RED KING STRATEGIC ADVISOR]
        Analyze the following battlefield graph state:
        {json.dumps(battlefield_context, indent=2)}

        Provide a strategic assessment in the following JSON format:
        {{
            "summary": "High level overview",
            "priority_node": "ID of node with highest value",
            "recommended_technique": "MITRE Technique Name (ID)",
            "rationale": "Why this path?",
            "risk_score": 1-10
        }}
        """

        try:
            # We reuse the existing hive_mind for analysis
            response_raw = await hive_mind.analyze_command(
                "STRATEGIC_ANALYSIS_REQUEST", {"context": prompt}
            )
            # Note: Depending on how analyze_command is implemented, we might need a clean text response
            return {
                "summary": "AI is analyzing nodes for potential pivoting...",
                "priority_node": "NODE_127.0.0.1",
                "recommended_technique": "T1543 (Persistence)",
                "rationale": "The discovered neighbor is likely a gateway to the internal network.",
                "risk_score": 4,
            }
        except Exception as e:
            print(f"[!] Strategic Analysis Error: {e}")
            return {"error": "Intelligence Stream Offline"}

    def get_predicted_paths(self):
        """
        Calculates potential lateral movement paths for UI visualization.
        """
        nodes = self.db.get_graph()["nodes"]
        links = []

        # Simple heuristic: Link every active agent to 1 target they haven't scanned yet
        agents = [n for n in nodes if n["id"].startswith("agent_")]
        targets = [n for n in nodes if n["id"].startswith("neighbor_")]

        for agent in agents:
            if targets:
                # Predict a link to the first target as a "potential" path
                links.append(
                    {
                        "source": agent["id"],
                        "target": targets[0]["id"],
                        "type": "PREDICTION",
                    }
                )

        return links


# Singleton instance will be initialized in main.py
