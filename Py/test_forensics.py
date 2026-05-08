import requests
import json

url = "http://localhost:9000/api/forensics/upload"
files = {"file": open("loot/test_vectors.pcap", "rb")}

print("[*] Uploading PCAP to Forensic Warlord...")
try:
    resp = requests.post(url, files=files)
    print(f"Status: {resp.status_code}")
    print("Report:")
    print(json.dumps(resp.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
