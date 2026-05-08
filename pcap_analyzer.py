from scapy.all import PcapReader, IP, TCP, UDP, Raw
from collections import Counter
import os
import time

PCAP_PATH = r"c:\salem\4.pcap"

def analyze_pcap(path):
    print(f"[*] Starting PCAP analysis: {path}", flush=True)
    if not os.path.exists(path):
        print("[-] File not found.", flush=True)
        return

    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    ports = Counter()
    
    # Keyword search in Raw layers
    keywords = ["password", "login", "user", "admin", "secret", "key"]
    leaks = []
    
    packet_count = 0
    start_time = time.time()
    LOG_EVERY = 250

    try:
        # Use PcapReader for streaming
        with PcapReader(path) as pcap_reader:
            print("[✓] PcapReader opened", flush=True)
            
            for pkt in pcap_reader:
                packet_count += 1
                
                # Production-safe logging logic
                if packet_count == 1:
                    print("[✓] First packet read", flush=True)
                    
                if packet_count % LOG_EVERY == 0:
                    elapsed = time.time() - start_time
                    rate = int(packet_count / elapsed) if elapsed > 0 else 0
                    print(f"[+] {packet_count} packets | {rate} pkt/s | {elapsed:.1f}s", flush=True)

                if IP in pkt:
                    protocols[pkt[IP].proto] += 1
                    src_ips[pkt[IP].src] += 1
                    dst_ips[pkt[IP].dst] += 1
                    
                    if TCP in pkt:
                        ports[pkt[TCP].dport] += 1
                    elif UDP in pkt:
                        ports[pkt[UDP].dport] += 1

                # Check for plain-text leaks
                if Raw in pkt:
                    try:
                        payload = str(pkt[Raw].load).lower()
                        for kw in keywords:
                            if kw in payload and len(leaks) < 20: 
                                leaks.append((kw, pkt[IP].src, pkt[IP].dst))
                    except:
                        pass
                        
    except Exception as e:
        print(f"\n[-] Error reading PCAP: {e}", flush=True)
        return

    print(f"\n[✓] Done. Total Packets Scanned: {packet_count}", flush=True)

    print("\n[+] Protocol Distribution (IP Proto Numbers):", flush=True)
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for proto, count in protocols.most_common(5):
        name = proto_map.get(proto, str(proto))
        print(f"    {name} ({proto}): {count} packets", flush=True)

    print("\n[+] Top Source IPs:", flush=True)
    for ip, count in src_ips.most_common(5):
        print(f"    {ip}: {count} packets", flush=True)

    print("\n[+] Top Destination IPs:", flush=True)
    for ip, count in dst_ips.most_common(5):
        print(f"    {ip}: {count} packets", flush=True)

    print("\n[+] Top Destination Ports:", flush=True)
    for port, count in ports.most_common(5):
        print(f"    Port {port}: {count} packets", flush=True)

    if leaks:
        print("\n[!] Potential Sensitive Data Found:", flush=True)
        for leak in leaks:
            print(f"    Keyword '{leak[0]}' found in traffic from {leak[1]} to {leak[2]}", flush=True)
    else:
        print("\n[+] No obvious plaintext credentials found with default keywords.", flush=True)

if __name__ == "__main__":
    analyze_pcap(PCAP_PATH)
