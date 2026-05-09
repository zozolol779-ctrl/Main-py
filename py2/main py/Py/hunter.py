import json
import time
import random
import uuid
from openai import OpenAI

class HunterAgent:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)
        self.logs = []
        
    def log(self, message, type="info"):
        entry = {"timestamp": time.strftime("%H:%M:%S"), "message": message, "type": type}
        self.logs.append(entry)
        print(f"[HUNTER] {message}")

    def think(self, target_node, system_prompt=None):
        """
        Decides on the next action based on the target node.
        """
        self.log(f"Analyzing target: {target_node['label']} ({target_node['type']})...", "thought")
        
        if system_prompt is None:
            # Default prompt if none provided
            system_prompt = """
            You are an autonomous OSINT Hunter Agent. Your goal is to gather intelligence on the target.
            """

        prompt = f"""
        {system_prompt}
        
        Target: {target_node['label']}
        Type: {target_node['type']}
        
        Available Tools:
        1. search_username: If target is a person or username. Checks social media.
        2. scan_ip: If target is an IP. Checks open ports and services.
        3. lookup_domain: If target is a domain. Checks Whois and DNS.
        4. deep_web_search: Searches for leaks or mentions in dark web dumps.
        
        Return ONLY a JSON object with the chosen tool and reasoning:
        {{
            "tool": "tool_name",
            "reasoning": "Why you chose this tool"
        }}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "system", "content": "You are a JSON-speaking intelligence agent."},
                          {"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            decision = json.loads(response.choices[0].message.content)
            self.log(f"Decision: {decision['reasoning']}", "thought")
            return decision['tool']
        except Exception as e:
            self.log(f"Thinking failed: {e}", "error")
            return None

    def execute(self, tool, target_node):
        """
        Executes the chosen tool (Mock implementation for now).
        """
        self.log(f"Executing tool: {tool}...", "action")
        time.sleep(2) # Simulate work
        
        new_data = {"nodes": [], "edges": []}
        
        if tool == "search_username":
            platforms = ["Twitter", "Instagram", "GitHub", "Reddit"]
            found = random.sample(platforms, k=random.randint(1, 3))
            for p in found:
                acc_id = str(uuid.uuid4())
                new_data["nodes"].append({
                    "id": acc_id, "label": f"{target_node['label']} ({p})", "type": "SocialMedia", 
                    "properties": {"platform": p, "url": f"https://{p.lower()}.com/{target_node['label']}"}
                })
                new_data["edges"].append({
                    "source": target_node['id'], "target": acc_id, "type": "HAS_ACCOUNT", "properties": {"confidence": 0.9}
                })
                
        elif tool == "scan_ip":
            ports = [22, 80, 443, 3306, 8080]
            open_ports = random.sample(ports, k=random.randint(1, 4))
            for p in open_ports:
                svc_id = str(uuid.uuid4())
                new_data["nodes"].append({
                    "id": svc_id, "label": f"Port {p}", "type": "Service", 
                    "properties": {"port": p, "status": "Open"}
                })
                new_data["edges"].append({
                    "source": target_node['id'], "target": svc_id, "type": "EXPOSES", "properties": {}
                })
                
        elif tool == "deep_web_search":
            if random.random() > 0.5:
                leak_id = str(uuid.uuid4())
                new_data["nodes"].append({
                    "id": leak_id, "label": "Breach Data", "type": "Leak", 
                    "properties": {"source": "RaidForums", "date": "2024-01-15"}
                })
                new_data["edges"].append({
                    "source": target_node['id'], "target": leak_id, "type": "APPEARED_IN", "properties": {"severity": "Critical"}
                })
                self.log("CRITICAL: Found leak data!", "alert")
            else:
                self.log("No leaks found.", "info")

        self.log(f"Tool finished. Found {len(new_data['nodes'])} new entities.", "success")
        return new_data
