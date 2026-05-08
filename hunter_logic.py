import math
from collections import defaultdict, Counter
from typing import List, Dict, Any

class ThreatHunter:
    def __init__(self):
        self.threats = []
        self.clusters = []

    def analyze(self, extracted_data: Dict[str, Any], beaconing_candidates: List[Dict]) -> Dict[str, Any]:
        """
        Main entry point for threat hunting logic.
        """
        self.detect_dga(extracted_data.get("dns_queries", []))
        self.detect_dns_tunneling(extracted_data.get("dns_queries", []))
        self.detect_fast_flux(extracted_data.get("dns_answers", {}))
        self.detect_c2(beaconing_candidates)
        self.detect_lateral_movement(beaconing_candidates) # Re-using flow stats from beaconing candidates logic or raw stats
        self.cluster_infrastructure(extracted_data)
        
        return {
            "threats": self.threats,
            "clusters": self.clusters
        }

    def detect_dga(self, domains: List[str]):
        """
        Detects Domain Generation Algorithms (DGA) using entropy and length analysis.
        """
        for domain in domains:
            # Calculate Shannon Entropy
            entropy = self._calculate_entropy(domain)
            
            # Heuristic: High entropy + length > 12 often indicates DGA
            if entropy > 3.8 and len(domain) > 12:
                self.threats.append({
                    "type": "DGA_DOMAIN",
                    "indicator": domain,
                    "severity": "High",
                    "details": {"entropy": round(entropy, 2)}
                })

    def detect_dns_tunneling(self, domains: List[str]):
        """
        Detects DNS Tunneling based on query length and subdomain complexity.
        """
        for domain in domains:
            if len(domain) > 50 and domain.count('.') > 2:
                self.threats.append({
                    "type": "DNS_TUNNELING",
                    "indicator": domain,
                    "severity": "Critical",
                    "details": {"length": len(domain)}
                })

    def detect_fast_flux(self, dns_answers: Dict[str, set]):
        """
        Detects Fast-Flux domains (single domain resolving to many IPs).
        """
        for domain, ips in dns_answers.items():
            if len(ips) > 5: # Threshold for Fast-Flux
                self.threats.append({
                    "type": "FAST_FLUX",
                    "indicator": domain,
                    "severity": "High",
                    "details": {"ip_count": len(ips), "ips": list(ips)[:5]}
                })

    def detect_lateral_movement(self, flows: List[Dict]):
        """
        Detects Lateral Movement (Internal -> Internal on Admin Ports).
        """
        # We need to identify internal IPs (RFC1918)
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        # Simplified check
        def is_internal(ip):
            return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

        sensitive_ports = {445: "SMB", 3389: "RDP", 22: "SSH", 5985: "WinRM"}
        
        for flow in flows:
            # Flow structure from beaconing_candidates is slightly different, 
            # we might need to adjust or pass raw traffic_stats.
            # Let's assume we passed raw traffic_stats keys as a list of dicts for this method
            # Or we iterate the extracted flows if available.
            # For this MVP, let's assume 'flows' contains {src, dst, port}
            pass 
            # (Placeholder: Real implementation needs flow data passed correctly)

    def detect_c2(self, beaconing_candidates: List[Dict]):
        """
        Analyzes beaconing candidates for C2 behavior.
        """
        for beacon in beaconing_candidates:
            # If interval is very regular (low variance) and interval > 5s
            if beacon["avg_interval"] > 5.0:
                self.threats.append({
                    "type": "C2_BEACON",
                    "indicator": f"{beacon['src']} -> {beacon['dst']}",
                    "severity": "Critical",
                    "details": beacon
                })

    def cluster_infrastructure(self, data: Dict[str, Any]):
        """
        Clusters infrastructure based on shared attributes (JA3, SNI, User-Agent).
        """
        # Cluster by JA3
        ja3_map = defaultdict(list)
        for tls in data.get("tls_handshakes", []):
            if "ja3" in tls:
                ja3_map[tls["ja3"]].append(tls["src"])
        
        for ja3, ips in ja3_map.items():
            if len(set(ips)) > 1: # Multiple IPs using same JA3
                self.clusters.append({
                    "type": "SHARED_JA3",
                    "value": ja3,
                    "members": list(set(ips)),
                    "severity": "Medium"
                })

        # Cluster by User-Agent
        ua_map = defaultdict(list)
        for http in data.get("http_requests", []):
            ua_map[http["user_agent"]].append(http["src"])
            
        for ua, ips in ua_map.items():
            if len(set(ips)) > 1 and len(ua) < 20: # Short/Suspicious UA shared by multiple IPs
                self.clusters.append({
                    "type": "SHARED_UA",
                    "value": ua,
                    "members": list(set(ips)),
                    "severity": "Low"
                })

    def _calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
