import time
import json
import os
import requests
import sys

LOG_FILE = "logs/access.log"
TARGET_MAP = "master_dna_map.json"
API_URL = "http://localhost:9001/api/alert"

def load_targets():
    if not os.path.exists(TARGET_MAP):
        return []
    with open(TARGET_MAP, "r") as f:
        data = json.load(f)
    return [t["ip"] for t in data]

def trigger_alert(ip, line):
    msg = f"⚠️ INTRUSION DETECTED: Target {ip} is active! Log: {line.strip()}"
    print(f"\n[🚨] {msg}")
    print("\a") # Beep
    try:
        requests.post(API_URL, json={"message": msg})
    except Exception as e:
        print(f"[!] Failed to push alert to API: {e}")

def main():
    print("[*] Alert System Online. Monitoring for 53 targets...")
    targets = load_targets()
    print(f"[*] Loaded {len(targets)} targets.")
    
    # Create log file if not exists
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    # Tail the log file
    f = open(LOG_FILE, "r")
    f.seek(0, os.SEEK_END)
    
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        
        for ip in targets:
            if ip in line:
                trigger_alert(ip, line)
                break

if __name__ == "__main__":
    main()
