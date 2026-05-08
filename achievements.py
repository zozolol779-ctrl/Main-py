from datetime import datetime
from typing import List, Dict


class Achievement:
    def __init__(self, id: str, name: str, description: str, icon: str):
        self.id = id
        self.name = name
        self.description = description
        self.icon = icon


ACHIEVEMENTS = {
    "FIRST_BLOOD": Achievement(
        "FIRST_BLOOD",
        "First Blood",
        "Established first persistent connection with a Ghost agent.",
        "Skull",
    ),
    "NETWORK_KING": Achievement(
        "NETWORK_KING",
        "Network King",
        "Discovered more than 10 unique network nodes.",
        "Network",
    ),
    "GRID_BREAKER": Achievement(
        "GRID_BREAKER",
        "Grid Breaker",
        "Triggered a SCADA kinetic strike command.",
        "Zap",
    ),
    "SOVEREIGN_MIND": Achievement(
        "SOVEREIGN_MIND",
        "Sovereign Mind",
        "Persisted battlefield data for over 24 hours.",
        "Brain",
    ),
}


class AchievementEngine:
    def __init__(self, db):
        self.db = db

    def evaluate(self) -> List[str]:
        """
        Evaluates the current state of SovereignDB and returns newly unlocked achievement IDs.
        """
        unlocked = self.db.db.get("achievements", {})
        newly_unlocked = []

        # 1. FIRST_BLOOD: Check if there's at least 1 agent
        if "FIRST_BLOOD" not in unlocked:
            if len(self.db.db.get("agents", {})) > 0:
                newly_unlocked.append("FIRST_BLOOD")

        # 2. NETWORK_KING: Check if nodes > 10
        if "NETWORK_KING" not in unlocked:
            if len(self.db.db.get("nodes", {})) > 10:
                newly_unlocked.append("NETWORK_KING")

        # 3. Handle Persistence of newly unlocked
        for aid in newly_unlocked:
            unlocked[aid] = datetime.now().isoformat()

        if newly_unlocked:
            self.db.db["achievements"] = unlocked
            self.db._save()

        return newly_unlocked

    def get_all_status(self) -> List[Dict]:
        unlocked = self.db.db.get("achievements", {})
        results = []
        for aid, achievement in ACHIEVEMENTS.items():
            results.append(
                {
                    "id": aid,
                    "name": achievement.name,
                    "description": achievement.description,
                    "icon": achievement.icon,
                    "unlocked": aid in unlocked,
                    "unlocked_at": unlocked.get(aid),
                }
            )
        return results
