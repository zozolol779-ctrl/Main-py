from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
import logging
from typing import List, Dict, Any, Generator
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class ScapyDeepExtractor:
    def __init__(self):
        pass

    def extract_from_pcap(self, pcap_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Stream packets from a PCAP file and yield extracted entities/events.
        Now supports OFFENSIVE FORENSICS (Credential Extraction).
        """
        logger.info(f"Starting deep packet extraction on: {pcap_path}")
        
        try:
            from scapy.utils import PcapReader
            
            with PcapReader(pcap_path) as pcap_reader:
                for packet in pcap_reader:
                    timestamp = datetime.fromtimestamp(float(packet.time)).isoformat()
                    
                    # 1. IP Layer Extraction
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        proto_num = packet[IP].proto
                        size = len(packet)
                        
                        yield {
                            "type": "TRAFFIC_FLOW",
                            "source": src_ip,
                            "target": dst_ip,
                            "protocol": proto_num,
                            "size": size,
                            "timestamp": timestamp
                        }

                        # 2. DNS Extraction
                        if packet.haslayer(DNS):
                            if packet.haslayer(DNSQR):
                                try:
                                    query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                                    yield {
                                        "type": "DNS_QUERY",
                                        "source": src_ip,
                                        "target": query,
                                        "timestamp": timestamp
                                    }
                                except Exception:
                                    pass
                            
                            if packet.haslayer(DNSRR):
                                try:
                                    rrname = packet[DNSRR].rrname.decode('utf-8').rstrip('.')
                                    rdata = packet[DNSRR].rdata
                                    if isinstance(rdata, str) and rdata.count('.') == 3:
                                        yield {
                                            "type": "DNS_RESOLUTION",
                                            "source": rrname,
                                            "target": rdata,
                                            "timestamp": timestamp
                                        }
                                except Exception:
                                    pass

                        # 3. OFFENSIVE LAYER: Credential Extraction
                        if packet.haslayer(Raw):
                            try:
                                payload = packet[Raw].load
                                payload_str = payload.decode('utf-8', errors='ignore')
                                lower_payload = payload_str.lower()
                                
                                cred_found = None
                                cred_type = None

                                # FTP
                                if 'USER ' in payload_str or 'PASS ' in payload_str:
                                    cred_type = "FTP"
                                    cred_found = payload_str.strip()[:100]
                                
                                # HTTP Basic
                                elif 'Authorization: Basic' in payload_str:
                                    cred_type = "HTTP_BASIC"
                                    cred_found = payload_str.split('Authorization: Basic')[1].split('\r\n')[0].strip()[:100]

                                # Telnet / Plaintext
                                elif 'login:' in lower_payload or 'password:' in lower_payload:
                                    cred_type = "TELNET_PLAINTEXT"
                                    cred_found = payload_str.strip()[:100]

                                if cred_found:
                                    yield {
                                        "type": "CREDENTIAL_EXPOSED",
                                        "source": src_ip,
                                        "target": dst_ip,
                                        "cred_type": cred_type,
                                        "value": cred_found,
                                        "timestamp": timestamp
                                    }
                            except Exception:
                                pass

        except Exception as e:
            logger.error(f"Error during PCAP extraction: {e}")
            raise
