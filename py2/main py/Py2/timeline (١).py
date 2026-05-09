from typing import List, Dict, Any
from datetime import datetime

class TimelineEngine:
    def __init__(self):
        self.events = []

    def build_timeline(self, extracted_data: Dict[str, Any]) -> List[Dict]:
        """
        Aggregates all timestamped events and sorts them.
        """
        # Collect events from all sources
        for http in extracted_data.get("http_requests", []):
            self.events.append({
                "timestamp": http["timestamp"],
                "type": "HTTP",
                "summary": f"HTTP {http['method']} {http['host']}{http['path']}",
                "src": http["src"],
                "dst": http["dst"]
            })
            
        for tls in extracted_data.get("tls_handshakes", []):
            self.events.append({
                "timestamp": tls["timestamp"],
                "type": "TLS",
                "summary": f"TLS Handshake to {tls['sni']}",
                "src": tls["src"],
                "dst": tls["dst"]
            })
            
        for file_tx in extracted_data.get("files", []):
            self.events.append({
                "timestamp": file_tx["timestamp"],
                "type": "FILE_TRANSFER",
                "summary": f"File Transfer ({file_tx['type']}) size={file_tx['size']}",
                "src": file_tx["src"],
                "dst": file_tx["dst"]
            })

        # Sort by timestamp
        self.events.sort(key=lambda x: x["timestamp"])
        return self.events

    def identify_phases(self) -> Dict[str, Any]:
        """
        Heuristically identifies attack phases.
        """
        if not self.events:
            return {}

        start_time = self.events[0]["timestamp"]
        end_time = self.events[-1]["timestamp"]
        duration = end_time - start_time
        
        phases = {
            "initial_access": None,
            "c2_start": None,
            "exfiltration": None
        }

        # Simple Heuristics
        for event in self.events:
            # First HTTP/TLS might be initial access or C2
            if not phases["initial_access"]:
                phases["initial_access"] = event["timestamp"]
            
            # If we see a file transfer, maybe payload delivery?
            if event["type"] == "FILE_TRANSFER" and not phases["c2_start"]:
                 # Just a guess for MVP
                 pass

        return {
            "start_time": datetime.fromtimestamp(start_time).isoformat(),
            "end_time": datetime.fromtimestamp(end_time).isoformat(),
            "duration_seconds": duration,
            "phases": phases
        }
