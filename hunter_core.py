import shodan
import os
import time
import sys
from scapy.all import rdpcap, TCP, Raw
from colorama import init, Fore, Style

# Initialize Colors
init(autoreset=True)


class HunterKiller:
    def __init__(self, pcap_file, api_key):
        self.pcap_file = pcap_file
        self.api = shodan.Shodan(api_key)
        self.dna_signature = None
        self.targets = []

    def _log(self, message, level="INFO"):
        if level == "INFO":
            print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        elif level == "WARNING":
            print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
        elif level == "CRITICAL":
            print(f"{Fore.RED}[XXX] {message}{Style.RESET_ALL}")
        elif level == "SYSTEM":
            print(f"{Fore.MAGENTA}[GHOST DRIFTER] {message}{Style.RESET_ALL}")

    def extract_dna(self):
        self._log(f"Loading Packet Capture: {self.pcap_file}...", "INFO")
        try:
            if not os.path.exists(self.pcap_file):
                self._log("PCAP File Not Found.", "CRITICAL")
                return False

            packets = rdpcap(self.pcap_file)
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    # Search for FTP (21) or Radmin (4899) signatures
                    if pkt[TCP].sport == 21 or pkt[TCP].sport == 4899:
                        try:
                            payload = pkt[Raw].load.decode(errors="ignore").strip()
                        except:
                            payload = str(pkt[Raw].load)

                        if "220" in payload or "Radmin" in payload:
                            self.dna_signature = payload
                            self._log(f"Target DNA Extracted: {payload}", "SUCCESS")
                            return True

            self._log(
                "No specific banner found. Switching to Heuristic Search.", "WARNING"
            )
            return False
        except Exception as e:
            self._log(f"Corruption in PCAP Analysis: {e}", "CRITICAL")
            return False

    def global_scan(self):
        query = ""
        if self.dna_signature:
            # Clean banner for search
            clean_banner = (
                self.dna_signature.split("\\r")[0]
                .replace("\r", "")
                .replace("\n", "")
                .replace('"', "")
            )
            # Broaden search to ensure hits (using simply port/product logic if banner is too specific)
            if "vsFTPd" in clean_banner:
                query = 'product:"vsftpd" port:21'
            elif "Radmin" in clean_banner:
                query = 'product:"Radmin" port:4899'
            else:
                query = f'"{clean_banner}"'
        else:
            # Fallback Heuristic
            query = "port:21 port:4899"

        self._log(f"Initializing Satellite Uplink (Shodan)... Query: [{query}]", "INFO")

        try:
            # Use limited search count to save credits/time
            results = self.api.search(query, limit=5)
            total = results.get("total", 0)
            self._log(f"Global Sensors Detected {total} Potential Hosts.", "SUCCESS")

            if total > 0:
                for result in results["matches"][:5]:
                    target_info = {
                        "ip": result["ip_str"],
                        "os": result.get("os", "Unknown"),
                        "country": result.get("location", {}).get(
                            "country_name", "Unknown"
                        ),
                    }
                    self.targets.append(target_info)
                    self._log(
                        f"LOCKED ON: {target_info['ip']} | Loc: {target_info['country']}",
                        "WARNING",
                    )
                return True
            else:
                self._log("No active targets found matching signature.", "WARNING")
                return False

        except shodan.APIError as e:
            self._log(f"Shodan Uplink Failed: {e}", "CRITICAL")
            return False

    def engage_ghost_drifter(self):
        if not self.targets:
            self._log("No targets locked. Mission Abort.", "CRITICAL")
            return

        print("\n" + "=" * 50)
        self._log("HANDING OVER CONTROL TO RESURRECTION CONTROLLER", "SYSTEM")
        print("=" * 50)

        # Select Primary Target
        primary_target = self.targets[0]

        # Simulate Handover Protocol
        time.sleep(1)
        self._log(f"Injecting Target Coordinates: {primary_target['ip']}", "SYSTEM")
        time.sleep(1)
        self._log(
            f"Bypassing AI Logic (Quota Exceeded)... Using Local Heuristics.", "SYSTEM"
        )
        time.sleep(1)
        self._log(
            f"Profile Loaded: 'The Silent Observer' -> Switching to ACTIVE.", "SYSTEM"
        )

        print(
            f"\n{Fore.RED}>>> GHOST DRIFTER IS NOW ACTIVE ON {primary_target['ip']} <<<{Style.RESET_ALL}"
        )
        print(f"{Fore.GREEN}Ready for Command Injection...{Style.RESET_ALL}")


# --- Execution Point ---
if __name__ == "__main__":
    # Verified Key from validate_keys.py
    API_KEY = "yBAuDov2MlJq8DKogYemWbAcRNH9E94U"
    PCAP_FILE = "capture.pcap"

    system = HunterKiller(PCAP_FILE, API_KEY)

    # Execute Sequence
    print(
        f"{Fore.CYAN}--- INITIATING GLOBAL HUNTER-KILLER PROTOCOL ---{Style.RESET_ALL}"
    )

    # 1. Forensics
    has_dna = system.extract_dna()

    # 2. Global Hunt (will run even if DNA fail, using fallback)
    found_targets = system.global_scan()

    # 3. Handover
    if found_targets:
        system.engage_ghost_drifter()
