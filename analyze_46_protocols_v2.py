from scapy.all import *

PCAP_FILE = "pcap2/sniffed-46.pcap"
TARGET_IP = "192.168.1.46"


def analyze_protocols_v2():
    print(f"[*] DEEP PROTOCOL ANALYSIS V2: {PCAP_FILE}")
    print(f"[*] TARGET IP: {TARGET_IP}")

    if not os.path.exists(PCAP_FILE):
        print("[!] PCAP file not found.")
        return

    # Read PCAP
    try:
        packets = rdpcap(PCAP_FILE)
        print(f"[+] Loaded {len(packets)} packets. Scanning for Secrets...")
    except Exception as e:
        print(f"[!] Error loading PCAP: {e}")
        return

    creds_found = []

    print("\n" + "=" * 50)
    print(" 🕵️ DECODED INTELLIGENCE STREAM")
    print("=" * 50)

    for i, pkt in enumerate(packets):
        if pkt.haslayer(IP) and pkt[IP].src == TARGET_IP:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")

                    # 1. FTP Analysis (Port 21)
                    if pkt[TCP].dport == 21:
                        if payload.startswith("USER") or payload.startswith("PASS"):
                            print(f"[FTP] Credential: {payload.strip()}")
                            creds_found.append(f"FTP: {payload.strip()}")

                    # 2. HTTP Analysis (Port 80/8080)
                    elif pkt[TCP].dport in [80, 8080]:
                        lines = payload.split("\r\n")
                        req_line = lines[0] if lines else "Unknown"
                        headers = [
                            l
                            for l in lines
                            if "User-Agent" in l
                            or "Cookie" in l
                            or "Authorization" in l
                        ]

                        if request_line_interesting(req_line):
                            print(f"[HTTP] Request: {req_line}")
                            for h in headers:
                                print(f"       {h}")
                                creds_found.append(f"HTTP: {h}")

                    # 3. Radmin/Binary Pattern (Port 4899)
                    elif pkt[TCP].dport == 4899:
                        # Just note activity, don't print raw binary
                        pass

                except Exception as e:
                    continue

    if not creds_found:
        print("\n[-] No cleartext credentials found.")
    else:
        print(f"\n[+] SUCCESS: {len(creds_found)} Secrets Extracted.")


def request_line_interesting(line):
    return "POST" in line or "GET" in line or "PUT" in line


if __name__ == "__main__":
    analyze_protocols_v2()
