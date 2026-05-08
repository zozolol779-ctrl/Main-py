import re
import os

PCAP_FILE = "../pcap2/sniffed-46.pcap"


def strings_dump():
    print(f"[*] Extracting Strings from {PCAP_FILE}...")
    try:
        if not os.path.exists(PCAP_FILE):
            print("[!] PCAP file not found.")
            return

        with open(PCAP_FILE, "rb") as f:
            data = f.read()
            # Regex for printable strings > 4 chars
            matches = re.findall(b"[a-zA-Z0-9_.-]{4,}", data)

            print(f"[+] Found {len(matches)} suspicious strings.")
            print("    Displaying top 30 interesting strings:")

            seen = set()
            count = 0
            for m in matches:
                s = m.decode(errors="ignore")
                # Filter out boring strings (too short, or common headers if needed)
                if s not in seen and len(s) < 100:
                    print(f"    - {s}")
                    seen.add(s)
                    count += 1
                    if count >= 30:
                        break

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    strings_dump()
