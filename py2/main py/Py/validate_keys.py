import requests
import os
import sys

# Force UTF-8 output if possible, but we will avoid non-ascii chars anyway
try:
    sys.stdout.reconfigure(encoding="utf-8")
except:
    pass

# --- AGGREGATED KEYS ---
KEYS = {
    "OpenAI (Updated)": "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",
    "Gemini (Updated)": "AIzaSyCQOfZBon4gPYYbli1ZPoWeE8j-bNeLWXc",
    "WhoisXML": "at_xyBamDqbBfQarhjx4dCLHL5GRbOON",
    "SecurityTrails": "Jr5tCoLejI7LzrpwxGQp2YWm0DPBSyVk",
    "IPInfo": "971cf20e8be3d3",
    "Shodan": "yBAuDov2MlJq8DKogYemWbAcRNH9E94U",
    "GitHub": "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",
    "VirusTotal": "9b54eeb772a6ab34214bedc8cb8848171d6f90c0bc7a7cba207e37435103bc97",
    "Hunter": "2f63d713186f51d6e133da6c269eb52c30d8da1b",
    "AbuseIPDB": "bf952267e20080fe0bf060509cbeb0d87db0fb3dfe112e8aac1d3d3d5ee37065e27b95bf9b095f1d",
}


def validate_all():
    print("=" * 60)
    print(" API AUDIT: VERIFYING SYSTEM CREDENTIALS")
    print("=" * 60)

    results = []

    # 1. OpenAI
    print("[*] Testing OpenAI...")
    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {KEYS['OpenAI (Updated)']}"},
            timeout=10,
        )
        if r.status_code == 200:
            results.append(("OpenAI", "ACTIVE", "Model List Access OK"))
        else:
            results.append(("OpenAI", "FAILED", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("OpenAI", "ERROR", str(e)))

    # 2. Gemini
    print("[*] Testing Gemini...")
    try:
        r = requests.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={KEYS['Gemini (Updated)']}",
            timeout=10,
        )
        if r.status_code == 200:
            results.append(("Gemini", "ACTIVE", "Generative Language API OK"))
        else:
            results.append(("Gemini", "FAILED", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("Gemini", "ERROR", str(e)))

    # 3. Shodan
    print("[*] Testing Shodan...")
    try:
        r = requests.get(
            f"https://api.shodan.io/api-info?key={KEYS['Shodan']}", timeout=10
        )
        if r.status_code == 200:
            info = r.json()
            results.append(
                ("Shodan", "ACTIVE", f"Credits: {info.get('query_credits')}")
            )
        else:
            results.append(("Shodan", "FAILED", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("Shodan", "ERROR", str(e)))

    # 4. IPInfo
    print("[*] Testing IPInfo...")
    try:
        r = requests.get(f"https://ipinfo.io/me?token={KEYS['IPInfo']}", timeout=10)
        if r.status_code == 200:
            results.append(("IPInfo", "ACTIVE", "Lookup OK"))
        else:
            results.append(("IPInfo", "FAILED", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("IPInfo", "ERROR", str(e)))

    # 5. GitHub
    print("[*] Testing GitHub...")
    try:
        # GitHub tokens often need specific headers
        headers = {
            "Authorization": f"Bearer {KEYS['GitHub']}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedKing-Sovereign",
        }
        r = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        if r.status_code == 200:
            user = r.json().get("login", "Unknown")
            results.append(("GitHub", "ACTIVE", f"User: {user}"))
        else:
            results.append(("GitHub", "FAILED", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("GitHub", "ERROR", str(e)))

    # 6. VirusTotal
    print("[*] Testing VirusTotal...")
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/files/non_existent_hash",
            headers={"x-apikey": KEYS["VirusTotal"]},
            timeout=10,
        )
        # 404 means the endpoint was reached and key accepted, just file not found (good)
        # 401 means forbidden (bad key)
        if r.status_code == 401:
            results.append(("VirusTotal", "FAILED", "Invalid Key"))
        elif r.status_code == 404:
            results.append(("VirusTotal", "ACTIVE", "Auth Validated"))
        else:
            results.append(("VirusTotal", "UNKNOWN", f"Status: {r.status_code}"))
    except Exception as e:
        results.append(("VirusTotal", "ERROR", str(e)))

    # Print Summary
    print("\n" + "=" * 60)
    print(" CREDENTIAL STATUS REPORT")
    print("=" * 60)
    print(f"{'SERVICE':<20} | {'STATUS':<10} | {'DETAILS'}")
    print("-" * 60)
    for res in results:
        print(f"{res[0]:<20} | {res[1]:<10} | {res[2]}")
    print("-" * 60)


if __name__ == "__main__":
    validate_all()
