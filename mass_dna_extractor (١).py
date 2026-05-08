import os
import json
from scapy.all import rdpcap, TCP, Raw

pcap_folder = "./pcap"
results = []
master_file = "master_dna_map.json"

print(f"[🚀] البدء في غربلة {len([f for f in os.listdir(pcap_folder) if f.endswith(('.pcap', '.pcapng'))])} ملف PCAP...")

for filename in os.listdir(pcap_folder):
    if filename.endswith((".pcap", ".pcapng")):
        path = os.path.join(pcap_folder, filename)
        try:
            # We use count=100 to avoid loading massive files entirely if we just need the banner
            packets = rdpcap(path, count=500) 
            for pkt in packets:
                if pkt.haslayer(Raw):
                    try:
                        payload = pkt[Raw].load.decode(errors='ignore')
                        # البحث عن أي بصمة ترحيب
                        if any(key in payload for key in ["220", "HTTP", "SSH", "Radmin", "FTP"]):
                            banner = payload.split('\n')[0].strip()
                            if "IP" in pkt:
                                ip_src = pkt["IP"].src
                                results.append({
                                    "file": filename,
                                    "ip": ip_src,
                                    "dna": banner
                                })
                                print(f"[+] Found DNA in {filename}: {ip_src} -> {banner[:50]}")
                                break # نكتفي بأول بصمة في كل ملف للتسريع
                    except:
                        continue
        except Exception as e:
            print(f"[!] خطأ في ملف {filename}: {e}")

# حفظ النتائج
with open(master_file, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=4, ensure_ascii=False)

print(f"\n[✅] اكتملت الغربلة! تم العثور على {len(results)} هدف محتمل.")
print(f"[💾] تم حفظ النتائج في {master_file}")
