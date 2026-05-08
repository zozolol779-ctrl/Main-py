import os
from scapy.all import *
from scapy.layers.inet import TCP, IP
import re

TARGET_IP = "192.168.1.46"
PCAP_DIR = "pcap"

print(f"[*] INITIATING DRAGNET SCAN for TARGET: {TARGET_IP}...")
print(f"[*] Looking for Tunnel Tokens & Cloud Credentials...")

found_pcaps = []

for filename in os.listdir(PCAP_DIR):
    if not filename.endswith((".pcap", ".pcapng", ".cap")):
        continue

    filepath = os.path.join(PCAP_DIR, filename)
    try:
        # Read only first 1000 packets to save time/memory for quick triage
        # count=1000 is safer for large files
        packets = rdpcap(filepath, count=500)

        has_target = False
        tokens_found = 0

        for pkt in packets:
            if IP in pkt:
                if pkt[IP].src == TARGET_IP or pkt[IP].dst == TARGET_IP:
                    has_target = True

                if pkt.haslayer(Raw):
                    payload = str(pkt[Raw].load)
                    # Check for Tunnels / Google / Cloud tokens
                    if (
                        "Authorization: Bearer" in payload
                        or "ngrok" in payload
                        or "googleapis" in payload
                    ):
                        tokens_found += 1

        if has_target:
            print(
                f"[+] MATCH: {filename} (Target Found, Potentially {tokens_found} tokens)"
            )
            found_pcaps.append((filename, tokens_found))

    except Exception as e:
        # print(f"[-] Error reading {filename}: {e}")
        pass

print("\n" + "=" * 50)
print("EXECUTION REPORT:")
print("=" * 50)
if found_pcaps:
    for f, count in found_pcaps:
        print(f"📄 {f} - Tokens: {count}")
    print(f"\n[recommendation] Analyze the file with the most tokens.")
else:
    print("[-] No direct trace of 192.168.1.46 found in the sample headers.")
