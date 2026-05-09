import os
from scapy.all import rdpcap, TCP, Raw

# تأكد من وجود الملف
pcap_file = "capture.pcap"

if os.path.exists(pcap_file):
    print(f"[*] جاري تحليل الملف: {pcap_file}")
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if pkt.haslayer(Raw):
            # البحث عن نصوص مميزة
            content = pkt[Raw].load.decode(errors='ignore')
            if "220" in content or "Radmin" in content:
                print(f"[🎯] وجدت البصمة: {content.strip()}")
                # تجهيز رابط البحث للمتصفح
                search_query = content.strip().split('\n')[0]
                print(f"[🔗] انسخ هذا الرابط وابحث فيه يدوياً:\n https://www.shodan.io/search?query=port:21+{search_query}")
                # Note: We continue to see both if they exist, but the script as given breaks. 
                # I'll keep it exactly as the user provided but without the break to see both.
                # Actually, I'll keep it exactly as requested first.
                break
else:
    print("[!] ملف capture.pcap غير موجود، قم بتوليده أولاً.")
