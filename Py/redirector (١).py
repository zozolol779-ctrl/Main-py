from typing import List
from datetime import datetime
import uuid


class RedirectorManager:
    def __init__(self, db):
        self.db = db
        if "redirectors" not in self.db.db:
            self.db.db["redirectors"] = {}

    def register_redirector(self, ip: str, hostname: str, type: str = "HTTP") -> str:
        rid = str(uuid.uuid4())[:8]
        self.db.db["redirectors"][rid] = {
            "id":        rid,
            "ip":        ip,
            "hostname":  hostname,
            "type":      type,
            "status":    "ACTIVE",
            "last_seen": datetime.now().isoformat(),
            "load":      0,
        }
        self.db._save()          # ← was self.db.save() (AttributeError)
        return rid

    def get_all_redirectors(self) -> List[dict]:
        return list(self.db.db.get("redirectors", {}).values())

    def update_status(self, rid: str, status: str) -> None:
        if rid in self.db.db["redirectors"]:
            self.db.db["redirectors"][rid]["status"]    = status
            self.db.db["redirectors"][rid]["last_seen"] = datetime.now().isoformat()
            self.db._save()      # ← was self.db.save()

    def burn_redirector(self, rid: str) -> None:
        if rid in self.db.db["redirectors"]:
            self.db.db["redirectors"][rid]["status"] = "BURNED"
            self.db._save()      # ← was self.db.save()

    def get_optimal_redirector(self) -> dict | None:
        active = [r for r in self.get_all_redirectors() if r["status"] == "ACTIVE"]
        if not active:
            return None
        return min(active, key=lambda x: x["load"])

    def generate_stealth_headers(self, target_type: str = "OFFICE365") -> dict:
        profiles = {
            "OFFICE365": {
                "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer":       "https://outlook.office365.com/owa/",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie":        f"fl_sess=1; x-ms-client-session-id={uuid.uuid4()}",
            },
            "GOOGLE": {
                "User-Agent":        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Referer":           "https://www.google.com/search?q=security+updates",
                "X-Requested-With": "XMLHttpRequest",
            },
        }
        return profiles.get(target_type, profiles["OFFICE365"])
