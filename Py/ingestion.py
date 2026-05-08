import os
import json
import logging
from datetime import datetime, timezone
import re
from typing import List, Dict, Any, Set

# Try importing scapy
try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    rdpcap = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IngestionEngine:
    def __init__(self):
        self.entities = {
            "ips": set(),
            "domains": set(),
            "emails": set(),
            "hashes": set(),
            "phones": set()
        }
        self.evidence_data = []

    def normalize_timestamp(self, ts: float) -> str:
        """Converts timestamp to UTC ISO format."""
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def normalize_ip(self, ip: str) -> str:
        return ip.strip()

    def normalize_domain(self, domain: str) -> str:
        return domain.lower().strip()

    def normalize_email(self, email: str) -> str:
        return email.lower().strip()

    def normalize_hash(self, file_hash: str) -> str:
        return file_hash.lower().strip()

    def process_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {}

        ext = file_path.split('.')[-1].lower()
        
        if ext in ['pcap', 'pcapng', 'cap']:
            return self._process_pcap(file_path)
        elif ext == 'json':
            return self._process_json(file_path)
        elif ext in ['txt', 'log']:
            return self._process_text(file_path)
        else:
            logger.warning(f"Unsupported file type: {ext}")
            return {}

    def _process_pcap(self, file_path: str) -> Dict[str, Any]:
        if not rdpcap:
            logger.error("Scapy not installed.")
            return {}
        
        logger.info(f"Processing PCAP: {file_path}")
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            return {}

        extracted = []

        for pkt in packets:
            if IP in pkt:
                src = self.normalize_ip(pkt[IP].src)
                dst = self.normalize_ip(pkt[IP].dst)
                ts = self.normalize_timestamp(float(pkt.time))
                
                self.entities["ips"].add(src)
                self.entities["ips"].add(dst)

                layer = "IP"
                if TCP in pkt: layer = "TCP"
                elif UDP in pkt: layer = "UDP"

                extracted.append({
                    "timestamp": ts,
                    "src": src,
                    "dst": dst,
                    "protocol": layer,
                    "length": len(pkt)
                })
        
        return {"type": "pcap", "count": len(extracted), "data": extracted}

    def _process_json(self, file_path: str) -> Dict[str, Any]:
        logger.info(f"Processing JSON: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {"type": "json", "data": data}
        except Exception as e:
            logger.error(f"Error reading JSON: {e}")
            return {}

    def _process_text(self, file_path: str) -> Dict[str, Any]:
        logger.info(f"Processing Text/Log: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Regex extraction
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            
            for ip in ips:
                self.entities["ips"].add(self.normalize_ip(ip))
            for email in emails:
                self.entities["emails"].add(self.normalize_email(email))

            return {"type": "text", "extracted_ips": len(ips), "extracted_emails": len(emails)}
        except Exception as e:
            logger.error(f"Error reading Text file: {e}")
            return {}

    def get_entities(self):
        return {k: list(v) for k, v in self.entities.items()}
