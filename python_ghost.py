import requests
import json
import time
import base64
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import uuid
import random

# --- CONFIG ---
C2_URL = "http://127.0.0.1:9000/api/hive/checkin"
SECRET_PASSPHRASE = b"RedKing_Global_Sovereignty_Protocol_2026"


# --- CRYPTO LAYER (Must match Server) ---
class RedCipher:
    def __init__(self, key_material):
        self.key = hashlib.sha256(key_material).digest()

    def encrypt(self, raw_data):
        if isinstance(raw_data, str):
            raw_data = raw_data.encode()
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(raw_data, AES.block_size))
        return base64.b64encode(iv + encrypted_data).decode("utf-8")

    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[: AES.block_size]
        cipher_text = enc_data[AES.block_size :]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cipher_text), AES.block_size).decode("utf-8")


# Generate Today's Key
today = datetime.now().strftime("%Y-%m-%d")
cipher = RedCipher(SECRET_PASSPHRASE + today.encode())
print(f"[*] Agent Initialized. Key Date: {today}")

# Create Dummy Agents
AGENTS = []
for i in range(3):
    uid = str(uuid.uuid4())
    AGENTS.append(
        {
            "agent_id": uid,
            "info": {
                "hostname": f"DESKTOP-{random.randint(1000,9999)}",
                "os": "Windows 11 Enterprise",
                "user": f"CORP\\User{i}",
                "neighbors": [
                    {
                        "ip": f"192.168.1.{random.randint(2, 254)}",
                        "mac": "00:11:22:33:44:55",
                    }
                    for _ in range(random.randint(1, 5))
                ],
            },
        }
    )


def check_in(agent):
    payload = {"agent_id": agent["agent_id"], "info": agent["info"]}

    # Encrypt
    json_str = json.dumps(payload)
    encrypted_data = cipher.encrypt(json_str)

    try:
        resp = requests.post(C2_URL, json={"data": encrypted_data})
        if resp.status_code == 200:
            print(f"[+] Agent {agent['agent_id'][:8]} Checked in.")
            # Verify Response Decryption
            try:
                resp_data = resp.json()
                if "data" in resp_data:
                    decrypted_orders = cipher.decrypt(resp_data["data"])
                    print(f"    [<] Orders Received: {decrypted_orders}")
            except Exception as e:
                print(f"    [!] Order Decryption Failed: {e}")
        else:
            print(f"[!] Check-in Failed: {resp.status_code}")
    except Exception as e:
        print(f"[!] Connection Refused: {e}")


# Run Loop
print("[*] Starting Traffic Simulation...")
while True:
    for agent in AGENTS:
        check_in(agent)
        time.sleep(1)
    time.sleep(2)
