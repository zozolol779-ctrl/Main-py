import json
import os
import re

TARGET_IP = "192.168.1.46"
POTENTIAL_NEW_TARGET = "192.168.1.64"
JSON_FILE = "../pcap2/pcap_to_json2.json"


def scan_deep():
    print(f"[*] DEEP SCAN V2: ANALYZING {JSON_FILE}...")
    print(f"[*] TARGET: {TARGET_IP} (Primary) | {POTENTIAL_NEW_TARGET} (Secondary)")

    hits_46 = 0
    hits_64 = 0
    tunnel_hits = 0

    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f):
                if TARGET_IP in line:
                    hits_46 += 1
                if POTENTIAL_NEW_TARGET in line:
                    hits_64 += 1

                # Check for sensitive keywords in payloads (hex or string)
                if "Authorization" in line or "Bearer" in line:
                    if hits_46 > 0 or hits_64 > 0:  # Correlation
                        print(f"[!] POTENTIAL CREDENTIAL FOUND at Line {line_num}")
                        print(f"    Context: {line.strip()[:100]}...")
                        tunnel_hits += 1

                if line_num % 500000 == 0 and line_num > 0:
                    print(f"[*] Processed {line_num} lines...")

    except Exception as e:
        print(f"[!] Error: {e}")

    print("\n" + "=" * 40)
    print("DEEP SCAN REPORT")
    print("=" * 40)
    print(f"Target {TARGET_IP} Hits: {hits_46}")
    print(f"Target {POTENTIAL_NEW_TARGET} Hits: {hits_64}")
    print(f"Tunnel Credentials Candidates: {tunnel_hits}")

    if hits_64 > hits_46:
        print(f"\n[!] ANALYSIS: The device {POTENTIAL_NEW_TARGET} is MUCH more active.")
        print("[!] It might be the new IP of your target.")

    print("[*] SCAN COMPLETE.")


if __name__ == "__main__":
    scan_deep()
