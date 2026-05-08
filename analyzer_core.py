import multiprocessing
import time
import json
import collections
from collections import Counter, defaultdict
from shared import LogType

# Optional imports with graceful fallback (though we expect them installed now)
try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw
    SCAPY_INSTALLED = True
except ImportError:
    SCAPY_INSTALLED = False

class AnalyzerCore(multiprocessing.Process):
    """
    Analyzer Core Engine - REAL IMPLEMENTATION.
    Runs in a dedicated PROCESS to handle heavy PCAP parsing.
    Ported from Antigravity's DeepPCAPAnalyzer.
    """
    def __init__(self, command_queue, result_queue, log_queue):
        super().__init__()
        self.command_queue = command_queue
        self.result_queue = result_queue
        self.log_queue = log_queue
        self.daemon = True

    def run(self):
        self._log(LogType.INFO, f"Analyzer Core Started (PID: {multiprocessing.current_process().pid}). Scapy Installed: {SCAPY_INSTALLED}")
        
        while True:
            try:
                cmd = self.command_queue.get()
                if cmd['type'] == 'LOAD_PCAP':
                    self._load_pcap(cmd['path'])
                elif cmd['type'] == 'STOP':
                    break
            except Exception as e:
                self._log(LogType.ERROR, f"Analyzer Critical Error: {e}")

    def _load_pcap(self, path):
        if not SCAPY_INSTALLED:
            self._log(LogType.ERROR, "Scapy not installed. Cannot analyze PCAP.")
            return

        self._log(LogType.INFO, f"Loading PCAP: {path} (Real Analysis)...")
        try:
            # 1. Load Packets
            # using sniff(offline=...) is often better for memory than rdpcap for large files if we iterated, 
            # but for this logic we load them to analyze. 
            # We limit to 20000 for performance safety in this version.
            packets = sniff(offline=path, count=20000)
            total = len(packets)
            self._log(LogType.INFO, f"Loaded {total} packets. Starting deep analysis...")

            # 2. Analyze Protocols & IPs
            protocols = Counter()
            src_ips = Counter()
            dst_ips = Counter()
            ports = Counter()
            credentials = []
            
            # For returning detailed flow data to frontend/hunter
            flows = [] # simplified list of dicts

            for pkt in packets:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    src_ips[src] += 1
                    dst_ips[dst] += 1
                    
                    proto_name = "Other"
                    sport = 0
                    dport = 0
                    
                    if TCP in pkt:
                        protocols['TCP'] += 1
                        proto_name = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        ports[dport] += 1
                    elif UDP in pkt:
                        protocols['UDP'] += 1
                        proto_name = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                    elif ICMP in pkt:
                        protocols['ICMP'] += 1
                        proto_name = "ICMP"
                    
                    # Store sample flow (limiting total flows to avoid freezing UI with huge JSON)
                    if len(flows) < 2000:
                        flows.append({
                            "src": src, "dst": dst, 
                            "proto": proto_name, 
                            "sport": sport, "dport": dport,
                            "time": float(pkt.time)
                        })

                    # 3. Credential Extraction (The "Offensive" Part)
                    if Raw in pkt:
                        load = pkt[Raw].load
                        try:
                            # Basic string decoding
                            payload_str = load.decode('utf-8', errors='ignore')
                            lower_payload = payload_str.lower()
                            
                            # FTP
                            if 'USER ' in payload_str or 'PASS ' in payload_str:
                                clean_cred = payload_str.strip()[:100]
                                if clean_cred not in credentials:
                                    credentials.append(f"FTP: {clean_cred}")
                            
                            # HTTP Basic
                            if 'Authorization: Basic' in payload_str:
                                clean_cred = payload_str.split('Authorization: Basic')[1].split('\r\n')[0].strip()[:100]
                                if f"HTTP Basic: {clean_cred}" not in credentials:
                                    credentials.append(f"HTTP Basic: {clean_cred}")

                            # Telnet / Plaintext Login
                            if 'login:' in lower_payload or 'password:' in lower_payload:
                                clean_cred = payload_str.strip()[:100]
                                if f"Plaintext: {clean_cred}" not in credentials:
                                    credentials.append(f"Plaintext: {clean_cred}")

                        except Exception:
                            pass

            self._log(LogType.SUCCESS, "Deep Analysis Complete.")
            if credentials:
                self._log(LogType.WARNING, f"FOUND {len(credentials)} CLEARTEXT CREDENTIALS!")

            # Prepare Stats Object
            stats = {
                "total_packets": total,
                "duration": f"{packets[-1].time - packets[0].time:.2f}s" if total > 1 else "0s",
                "protocols": dict(protocols),
                "top_ips": [ip for ip, _ in src_ips.most_common(10)],
                "credentials": credentials,
                "flows_sample": flows
            }
            
            # Send results back
            self.result_queue.put({"type": "PCAP_STATS", "data": stats})
            
            # Also send extracted data for Hunter Logic
            # We can send a separate event or include it. 
            # For now, let's assume the main process forwards relevant parts to Hunter.
            
        except Exception as e:
            self._log(LogType.ERROR, f"Failed to analyze PCAP: {e}")

    def _log(self, level, message):
        self.log_queue.put({"level": level.value, "message": message, "source": "Analyzer"})

