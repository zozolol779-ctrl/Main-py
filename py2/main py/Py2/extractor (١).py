import logging
from typing import List, Dict, Any
from collections import defaultdict
import hashlib

# Try importing scapy layers
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
except ImportError:
    pass

logger = logging.getLogger(__name__)

class DeepExtractor:
    def __init__(self):
        self.extracted_data = {
            "dns_queries": set(),
            "http_requests": [],
            "tls_handshakes": [],
            "smtp_traffic": [],
            "files": []
        }
        self.traffic_stats = defaultdict(list) # Key: (src, dst), Value: [timestamps]

    def extract_from_pcap(self, packets) -> Dict[str, Any]:
        """
        Performs deep extraction on a list of Scapy packets.
        """
        logger.info("Starting Deep Packet Extraction...")
        
        for pkt in packets:
            if IP not in pkt:
                continue
                
            src = pkt[IP].src
            dst = pkt[IP].dst
            ts = float(pkt.time)
            
            # Traffic Stats for Beaconing Detection
            # Also record ports for Lateral Movement
            dst_port = 0
            if TCP in pkt: dst_port = pkt[TCP].dport
            elif UDP in pkt: dst_port = pkt[UDP].dport
            
            self.traffic_stats[(src, dst, dst_port)].append(ts)

            # DNS Extraction (Queries & Answers)
            if DNS in pkt:
                if pkt.haslayer(DNSQR):
                    query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    self.extracted_data["dns_queries"].add(query)
                
                # Extract DNS Answers for Fast-Flux
                if pkt.haslayer(DNSRR):
                    # Scapy can have multiple RR layers. We need to iterate or check ancount.
                    # Simplified: Check the first RR if it's an A record (type 1)
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNS].an[i]
                        if rr.type == 1: # A Record
                            rr_name = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                            rr_ip = rr.rdata
                            if "dns_answers" not in self.extracted_data:
                                self.extracted_data["dns_answers"] = defaultdict(set)
                            self.extracted_data["dns_answers"][rr_name].add(rr_ip)
            
            # HTTP Extraction
            if pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                host = http.Host.decode('utf-8', errors='ignore') if http.Host else ""
                path = http.Path.decode('utf-8', errors='ignore') if http.Path else ""
                ua = http.User_Agent.decode('utf-8', errors='ignore') if http.User_Agent else ""
                method = http.Method.decode('utf-8', errors='ignore') if http.Method else ""
                
                self.extracted_data["http_requests"].append({
                    "timestamp": ts,
                    "src": src,
                    "dst": dst,
                    "host": host,
                    "path": path,
                    "user_agent": ua,
                    "method": method
                })

            # TLS Extraction (Advanced: JA3 & Cipher Suites)
            if pkt.haslayer(TLSClientHello):
                try:
                    client_hello = pkt[TLSClientHello]
                    sni = client_hello.server_name.decode('utf-8', errors='ignore') if client_hello.server_name else ""
                    
                    # Extract JA3 components
                    # JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
                    # Note: Scapy's TLS layer naming might vary slightly depending on version.
                    
                    tls_version = client_hello.version
                    ciphers = client_hello.ciphers
                    extensions = client_hello.extensions
                    
                    # Simplified JA3 generation (Concept)
                    # Real JA3 requires precise decimal values joined by dashes/commas
                    ja3_string = f"{tls_version},{'-'.join(map(str, ciphers))},{'-'.join(map(str, [e.type for e in extensions]))},,"
                    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
                    
                    self.extracted_data["tls_handshakes"].append({
                        "timestamp": ts,
                        "src": src,
                        "dst": dst,
                        "sni": sni,
                        "version": tls_version,
                        "ja3": ja3_hash,
                        "ja3_string": ja3_string, # For debugging
                        "ciphers": len(ciphers)
                    })
                except Exception as e:
                    # TLS parsing can be fragile
                    pass

            # File Extraction (Heuristic based on size/payload)
            # This is a simplified placeholder. Real file extraction requires stream reassembly.
            if TCP in pkt and len(pkt[TCP].payload) > 1000:
                payload = bytes(pkt[TCP].payload)
                # Check for common file headers
                if payload.startswith(b'%PDF'):
                    self._record_file(src, dst, ts, payload, "pdf")
                elif payload.startswith(b'MZ'):
                    self._record_file(src, dst, ts, payload, "exe")
        
        return self.extracted_data

    def _record_file(self, src, dst, ts, payload, file_type):
        md5 = hashlib.md5(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        self.extracted_data["files"].append({
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "type": file_type,
            "size": len(payload),
            "md5": md5,
            "sha256": sha256
        })

    def analyze_traffic_patterns(self):
        """
        Analyzes traffic stats for beaconing (periodic connections).
        """
        beaconing_candidates = []
        for conn, timestamps in self.traffic_stats.items():
            if len(timestamps) < 10:
                continue
            
            timestamps.sort()
            deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            # Calculate variance of deltas
            avg_delta = sum(deltas) / len(deltas)
            variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
            
            # Low variance implies periodicity (Beaconing)
            if variance < 1.0 and avg_delta > 1.0:
                beaconing_candidates.append({
                    "src": conn[0],
                    "dst": conn[1],
                    "avg_interval": avg_delta,
                    "confidence": "High"
                })
                
        return beaconing_candidates
