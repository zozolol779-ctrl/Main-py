from scapy.all import *
import binascii
import os

PCAP_FILE = "pcap2/sniffed-46.pcap"


def hex_dump(data, length=16):
    filter = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
    lines = []
    for c in range(0, len(data), length):
        chars = data[c : c + length]
        hex = " ".join(f"{x:02x}" for x in chars)
        printable = "".join(["%s" % ((x <= 127 and filter[x]) or ".") for x in chars])
        lines.append(f"{c:04x}  {hex:<{length*3}}  {printable}")
    return "\n".join(lines)


def dump_radmin_traffic():
    print(f"[*] Analyzing Radmin Traffic (Port 4899) in {PCAP_FILE}...")

    if not os.path.exists(PCAP_FILE):
        print("[!] PCAP file not found.")
        return

    packets = rdpcap(PCAP_FILE)
    conversation_count = 0

    print("\n" + "=" * 50)
    print(" RADMIN SESSION DUMP (Native Mode)")
    print("=" * 50)

    for pkt in packets:
        if pkt.haslayer(TCP) and (pkt[TCP].sport == 4899 or pkt[TCP].dport == 4899):
            if pkt.haslayer(Raw):
                conversation_count += 1
                src = pkt[IP].src
                dst = pkt[IP].dst
                payload = pkt[Raw].load

                print(
                    f"\n[Packet {conversation_count}] {src} -> {dst} | Len: {len(payload)}"
                )
                print(hex_dump(payload))

                if conversation_count >= 10:
                    print("\n[!] Limit reached (10 packets).")
                    break

    if conversation_count == 0:
        print("[-] No Radmin payloads found.")


if __name__ == "__main__":
    dump_radmin_traffic()
