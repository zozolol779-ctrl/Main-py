import json                          # ← was missing at module level; analyze_recon() used
import os                             #   json.loads() without importing it, causing NameError
from typing import Dict, Any, List

import google.generativeai as genai
from dotenv import load_dotenv

from .logger import logger

load_dotenv()


class LLMCommander:
    """
    Hive Mind – consults Generative AI for strategic advice.
    Text-only interface; does not execute commands.
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

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _clean_llm_response(self, text: str) -> List[str]:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("\n", 1)[0]
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return [line for line in text.split("\n") if line.strip()]

    # ── Public API ────────────────────────────────────────────────────────────

    async def analyze_and_command(
        self, agent_id: str, recon_data: Dict[str, Any]
    ) -> List[str]:
        if not self.model:
            return ["echo 'AI Offline - Defaulting to Idle'"]

        prompt = (
            f"[SYSTEM: RED KING STRATEGIC ADVISOR]\n"
            f"Agent: {agent_id}\nRecon: {recon_data}\n"
            f"Return ONLY a JSON list of safe shell commands to assess posture."
        )
        try:
            response = self.model.generate_content(prompt)
            return self._clean_llm_response(response.text)
        except Exception as exc:
            logger.error(f"[-] AI Thinking Error: {exc}")
            return ["whoami"]

    async def analyze_recon(self, recon_type: str, data: str) -> dict:
        if not self.model:
            return {"command": None, "risk": "UNKNOWN", "reason": "AI offline"}
        try:
            prompt = (
                f"SYSTEM: Strategic C2 AI.\n"
                f"INTEL TYPE: {recon_type}\nRAW DATA: {data}\n\n"
                f"Analyze data. Output JSON: "
                f'{{ "command": "string", "risk": "LOW|HIGH", "reason": "string" }}\n'
                f"RESPONSE FORMAT: JSON ONLY"
            )
            response = self.model.generate_content(prompt)
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)          # ← previously crashed with NameError
        except Exception as exc:
            return {"command": None, "risk": "UNKNOWN", "reason": f"Analysis failed: {exc}"}

    async def analyze_target(self, dna: str, title: str) -> dict:
        if not self.model:
            return {
                "device_type":   "Unknown (AI Offline)",
                "threat_level":  "UNKNOWN",
                "attack_vector": "Manual analysis required.",
            }
        clean_dna = dna[:500] if dna else "UNKNOWN"
        prompt = (
            f"Analyze this target's DNA banner and page title.\n"
            f"DNA: {clean_dna}\nTitle: {title}\n\n"
            f"Return JSON ONLY:\n"
            f'{{"device_type": "string", "threat_level": "Low|Medium|High|Critical", '
            f'"attack_vector": "string"}}'
        )
        try:
            response = self.model.generate_content(prompt)
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as exc:
            logger.error(f"[-] AI Analysis Failed: {exc}")
            return {
                "device_type":   "Analysis Failed",
                "threat_level":  "UNKNOWN",
                "attack_vector": str(exc),
            }

    async def get_strategic_advice(self, query: str) -> str:
        if not self.model:
            return "❌ Hive Mind Offline. Check GEMINI_API_KEY."
        prompt = (
            f"You are 'Red King', a C2 Strategic Advisor. Text interface only – "
            f"do not execute anything.\n\n"
            f"USER QUERY: {query}\n\n"
            f"Reply concisely. Detect language and reply in same language."
        )
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as exc:
            err = str(exc)
            if "429" in err or "Quota" in err:
                return "⚠️ NEURAL LINK UNSTABLE (429) – Rate limit hit. Try again shortly."
            return f"[-] Neural Link Error: {exc}"


# Singleton
hive_mind = LLMCommander()
