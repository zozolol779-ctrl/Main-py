from scapy.all import *
from scapy.layers.inet import TCP, IP

# 1. Simulate FTP Server Greeting (DNA Signature)
pkt1 = (
    IP(src="192.168.1.46", dst="192.168.1.10")
    / TCP(sport=21, dport=5566, flags="PA")
    / Raw(load="220 (vsFTPd 3.0.3)\r\n")
)

# 2. Simulate Radmin Server Response
pkt2 = (
    IP(src="192.168.1.46", dst="192.168.1.10")
    / TCP(sport=4899, dport=4455, flags="PA")
    / Raw(load="Radmin v3.5 Server\x00\x01\x02")
)

# 3. Write to 'capture.pcap' in the current directory so hunter_core can find it
wrpcap("capture.pcap", [pkt1, pkt2])
print("[+] Created Forensic Evidence: capture.pcap with FTP/Radmin signatures.")
