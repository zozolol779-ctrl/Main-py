import sys
import os

# Add backend to path
sys.path.append(os.getcwd())

from main import run_investigation, SCAPY_INSTALLED

print(f"[*] Scapy Installed: {SCAPY_INSTALLED}")

pcap_path = r"C:\Users\mido7\.gemini\antigravity\scratch\pcap_ai_analyzer\10.pcap"

if not os.path.exists(pcap_path):
    print(f"[!] Error: PCAP not found at {pcap_path}")
    sys.exit(1)

print(f"[*] Starting Analysis on: {pcap_path}")
print("[*] (This uses the new Real Power engines...)")

try:
    results = run_investigation(pcap_path)
    
    print("\n" + "="*50)
    print("✅ ANALYSIS COMPLETE - SUPER TOOL ENGINE")
    print("="*50)
    print(f"Status: {results['status']}")
    print(f"Threats Found: {results['threats']}")
    
    if results.get('details'):
        print("\n🚨 THREATS DETECTED:")
        for t in results['details']:
            print(f"  - [{t.get('severity')}] {t.get('type')}: {t.get('details')}")
    else:
        print("\nNo threats detected (or not implemented locally).")
        
    print("\n" + "="*50)

except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
    import traceback
    traceback.print_exc()
