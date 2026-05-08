import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from .prompts import SYSTEM_PROMPT, TASK_PROMPT_TEMPLATE
from .tools import ToolRegistry

# Mock OpenAI client for now
class MockOpenAI:
    def chat_completion(self, messages):
        # returns a dummy JSON response to simulate agent thought
        last_msg = messages[-1]['content']
        if "investigate" in last_msg.lower():
            return json.dumps({
                "thought": "I need to check the reputation of the target IP.",
                "hypothesis": "Target IP is malicious.",
                "tool_name": "enrich_entity",
                "tool_args": {"value": "192.168.1.5", "type": "ip"}
            })
        return json.dumps({
            "thought": "The IP is suspicious. I should conclude the investigation.",
            "hypothesis": "Confirmed malicious activity.",
            "tool_name": "finish_investigation",
            "tool_args": {"verdict": "MALICIOUS", "summary": "Found C2 traces."}
        })

class HunterAgent:
    def __init__(self, agent_id: str, db: Optional[Session] = None, model: str = "gpt-4-turbo"):
        self.agent_id = agent_id
        self.model = model
        self.db = db
        self.tools = ToolRegistry(db=db)
        self.history = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.max_steps = 10
        # Initialize OpenAI client here
        # self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    async def run_investigation(self, target: str, context: str = "") -> Dict[str, Any]:
        """Main entry point for the agent."""
        task_prompt = TASK_PROMPT_TEMPLATE.format(target=target, context=context)
        self.history.append({"role": "user", "content": task_prompt})
        
        steps = []
        
        for i in range(self.max_steps):
            # 1. Think (Call LLM)
            response_text = await self._call_llm()
            
            try:
                action_data = json.loads(response_text)
            except json.JSONDecodeError:
                # Handle parsing error, maybe retry
                continue
                
            steps.append({
                "step": i + 1,
                "timestamp": datetime.now().isoformat(),
                "thought": action_data.get("thought"),
                "action": action_data.get("tool_name"),
                "args": action_data.get("tool_args")
            })

            # Check if finished
            if action_data.get("tool_name") == "finish_investigation":
                return {
                    "status": "completed",
                    "verdict": action_data["tool_args"].get("verdict"),
                    "summary": action_data["tool_args"].get("summary"),
                    "steps": steps
                }

            # 2. Act (Execute Tool)
            tool_name = action_data.get("tool_name")
            tool_args = action_data.get("tool_args", {})
            
            observation = await self.tools.execute(tool_name, tool_args)
            
            # 3. Observe (Feed back to LLM)
            observation_msg = f"Observation from {tool_name}: {json.dumps(observation)}"
            self.history.append({"role": "assistant", "content": response_text})
            self.history.append({"role": "user", "content": observation_msg})
            
        return {"status": "timeout", "steps": steps}

    async def _call_llm(self) -> str:
        """Call the LLM API."""
        # return self.client.chat.completions.create(model=self.model, messages=self.history).choices[0].message.content
        
        # Using Mock for now so user can run it without API key immediately
        mock = MockOpenAI()
        return mock.chat_completion(self.history)
