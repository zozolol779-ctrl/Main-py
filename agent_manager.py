import os
import yaml
from typing import List, Dict, Optional

class AgentManager:
    def __init__(self, agents_dir: str = "agents"):
        self.agents_dir = agents_dir
        self.agents = {}
        self.load_agents()

    def load_agents(self):
        """Loads agent definitions from markdown files with YAML frontmatter."""
        if not os.path.exists(self.agents_dir):
            os.makedirs(self.agents_dir)
            return

        for filename in os.listdir(self.agents_dir):
            if filename.endswith(".md"):
                path = os.path.join(self.agents_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    # Simple frontmatter parser
                    if content.startswith("---"):
                        parts = content.split("---", 2)
                        if len(parts) >= 3:
                            metadata = yaml.safe_load(parts[1])
                            system_prompt = parts[2].strip()
                            
                            agent_id = filename.replace(".md", "")
                            self.agents[agent_id] = {
                                "id": agent_id,
                                "name": metadata.get("name", agent_id),
                                "description": metadata.get("description", ""),
                                "model": metadata.get("model", "gpt-4o"),
                                "system_prompt": system_prompt
                            }
                except Exception as e:
                    print(f"Error loading agent {filename}: {e}")

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        return self.agents.get(agent_id)

    def list_agents(self) -> List[Dict]:
        return [{"id": k, **v} for k, v in self.agents.items()]
