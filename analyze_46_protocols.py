from scapy.all import *

PCAP_FILE = "pcap2/sniffed-46.pcap"


def analyze_protocols():
    print(f"[*] DEEP PROTOCOL ANALYSIS: {PCAP_FILE}")
    print("    Targeting: FTP (21), HTTP (80), POP3/IMAP")

    if not os.path.exists(PCAP_FILE):
        print("[!] PCAP file not found.")
        return

    packets = rdpcap(PCAP_FILE)

    creds_found = []

    print("\n" + "=" * 50)
    print(" INTERCEPTED CREDENTIALS & COMMANDS")
    print("=" * 50)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")

            # FTP Analysis
            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                if "USER " in payload or "PASS " in payload:
                    print(f"[FTP] {pkt[IP].src} -> {pkt[IP].dst}: {payload.strip()}")
                    creds_found.append(payload.strip())

            # HTTP Analysis
            elif pkt[TCP].dport == 80:
                if (
                    "POST " in payload
                    or "Authorization:" in payload
                    or "Cookie:" in payload
                ):
                    print(f"[HTTP] {pkt[IP].src} -> {pkt[IP].dst}")
                    # Print first 200 chars of interesting payloads
                    print(
                        f"       {payload[:200].replace(chr(10), ' ').replace(chr(13), '')}..."
                    )

            # Basic String Search for "password" or "key"
            if "password" in payload.lower() or "passwd" in payload.lower():
                print(f"[LEAK] {pkt[IP].src} -> {pkt[IP].dst}: {payload.strip()[:100]}")

    if not creds_found:
        print("\n[-] No cleartext legacy credentials (FTP/Telnet) found.")
        print("    Target might be using encrypted channels or custom binaries.")


if __name__ == "__main__":
    analyze_protocols()
