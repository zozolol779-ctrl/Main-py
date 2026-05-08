import random
from typing import List, Dict, Optional
from enum import Enum
from pydantic import BaseModel

class Tactic(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

class AgentContext(BaseModel):
    agent_id: str
    os_type: str  # "windows", "linux"
    is_admin: bool
    stealth_required: bool = True
    current_tactic: Tactic = Tactic.DISCOVERY

class AttackModules:
    """Database of MITRE ATT&CK Techniques mapped to Code Modules"""
    WINDOWS_MODULES = {
        Tactic.DISCOVERY: [
            {"id": "T1082", "name": "System Info Discovery", "cmd": "systeminfo", "noise": 10},
            {"id": "T1057", "name": "Process Discovery", "cmd": "tasklist", "noise": 20},
            {"id": "T1012", "name": "Query Registry", "cmd": "reg query HKLM", "noise": 40},
        ],
        Tactic.PERSISTENCE: [
            {"id": "T1053", "name": "Scheduled Task", "cmd": "schtasks /create ...", "noise": 80},
            {"id": "T1547", "name": "Registry Run Keys", "cmd": "reg add HKCU\\...\\Run ...", "noise": 60},
        ],
        Tactic.CREDENTIAL_ACCESS: [
            {"id": "T1003", "name": "OS Credential Dumping (LSASS)", "cmd": "procdump lsass", "noise": 100},
            {"id": "T1555", "name": "Credentials from Browser", "cmd": "grab_chrome_cookies", "noise": 30},
        ]
    }
    
    LINUX_MODULES = {
        Tactic.DISCOVERY: [
            {"id": "T1082", "name": "System Info", "cmd": "uname -a", "noise": 5},
            {"id": "T1033", "name": "Local User Discovery", "cmd": "cat /etc/passwd", "noise": 10},
        ]
    }

class AiGeneral:
    """
    🧠 The Autonomous Decision Logic
    Calculates the 'Next Best Move' based on probability and risk.
    """
    
    @staticmethod
    def decide_next_move(ctx: AgentContext) -> Dict:
        print(f"[*] [AI GENERAL] Analyzing context for Agent: {ctx.agent_id} ({ctx.os_type})")
        
        # 1. Select Module Database
        db = AttackModules.WINDOWS_MODULES if "win" in ctx.os_type.lower() else AttackModules.LINUX_MODULES
        
        # 2. Determine Goal based on state
        next_tactic = ctx.current_tactic
        
        # Simple State Machine Logic (Professional logic would be a Graph Traversal)
        if ctx.current_tactic == Tactic.DISCOVERY:
            # After discovery, try to escalate or persist
            next_tactic = Tactic.PERSISTENCE if not ctx.is_admin else Tactic.CREDENTIAL_ACCESS
            
        available_moves = db.get(next_tactic, [])
        if not available_moves:
             # Fallback
             return {"action": "WAIT", "reason": "No modules available for this tactic"}

        # 3. Calculate Risk/Reward
        best_move = None
        lowest_risk_score = 999
        
        print(f"   |-- Goal: {next_tactic.value}")
        
        for move in available_moves:
            risk_score = move['noise']
            
            # Modifier: If we are admin, we can afford more noise? No, usually Admin needs to stay hidden too.
            # Modifier: If stealth is required, penalty for high noise is doubled.
            if ctx.stealth_required:
                risk_score *= 2
                
            print(f"       |-- Evaluating: {move['name']} (Risk: {risk_score})")
            
            if risk_score < lowest_risk_score:
                lowest_risk_score = risk_score
                best_move = move

        if best_move:
            return {
                "action": "EXECUTE",
                "tactic": next_tactic,
                "technique": best_move['name'],
                "mitre_id": best_move['id'],
                "command": best_move['cmd'],
                "reason": f"Selected optimal move with lowest risk score ({lowest_risk_score})"
            }
            
        return {"action": "SLEEP", "reason": "Too risky to proceed"}

# --- Simulation Test ---
if __name__ == "__main__":
    # Simulate a compromised Agent
    agent_ctx = AgentContext(
        agent_id="ghost-001", 
        os_type="windows", 
        is_admin=False, 
        stealth_required=True,
        current_tactic=Tactic.DISCOVERY
    )
    
    decision = AiGeneral.decide_next_move(agent_ctx)
    print("\n[+] [RED KING DECISION]:")
    print(decision)
