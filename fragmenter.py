import time
from typing import Dict, Optional, List
import hashlib


class PayloadFragmenter:
    def __init__(self):
        # {session_id: {part_index: data, total: count, timestamp: time}}
        self.buffer: Dict[str, Dict] = {}
        self.ttl = 300  # 5 minutes to complete reassembly

    def add_fragment(
        self, session_id: str, part_index: int, total_parts: int, data: str
    ) -> Optional[str]:
        """
        Adds a fragment to the buffer. Returns the full reassembled payload if complete.
        """
        now = time.time()

        # Cleanup old sessions
        self._cleanup()

        if session_id not in self.buffer:
            self.buffer[session_id] = {
                "parts": {},
                "total": total_parts,
                "timestamp": now,
            }

        session = self.buffer[session_id]
        session["parts"][part_index] = data
        session["timestamp"] = now

        # Check if complete
        if len(session["parts"]) == session["total"]:
            # Reassemble in order
            ordered_parts = [session["parts"][i] for i in range(session["total"])]
            full_payload = "".join(ordered_parts)

            # Remove from buffer once reassembled
            del self.buffer[session_id]
            return full_payload

        return None

    def _cleanup(self):
        now = time.time()
        expired = [
            sid
            for sid, data in self.buffer.items()
            if now - data["timestamp"] > self.ttl
        ]
        for sid in expired:
            del self.buffer[sid]

    def get_stats(self):
        return {
            "active_sessions": len(self.buffer),
            "fragments_buffered": sum(len(s["parts"]) for s in self.buffer.values()),
        }
