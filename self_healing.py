import os
import time
import threading
from datetime import datetime


class SelfHealingSystem:
    def __init__(self, db):
        self.db = db
        self.health_log = []
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            print("[*] Self-Healing Protocol: ENGAGED")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            self._perform_health_checks()
            time.sleep(60)  # Run every minute

    def _perform_health_checks(self):
        timestamp = datetime.now().strftime("%H:%M:%S")
        issues = []

        # 1. Check Persistence Storage
        if not os.path.exists("persistence/graph.json"):
            issues.append("Persistence Graph Missing")
            # Auto-healing: DB singleton creator usually handles this, but we log it

        # 2. Check Asset Directories
        if not os.path.exists("loot"):
            os.makedirs("loot")
            issues.append("Loot Directory Missing -> RECONSTRUCTED")

        if issues:
            for issue in issues:
                self.health_log.append(f"[{timestamp}] ISSUE: {issue}")
                print(f"[!] Self-Healing [{timestamp}]: {issue}")
        else:
            # Silent health confirm
            pass

    def get_health_status(self):
        return {
            "status": "HEALTHY" if not self.health_log else "STABILIZING",
            "last_check": datetime.now().isoformat(),
            "incidents": self.health_log[-10:],  # Last 10 incidents
        }


# Will be initialized in main.py
