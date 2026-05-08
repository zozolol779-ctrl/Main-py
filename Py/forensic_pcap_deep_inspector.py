#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Deep PCAP forensic inspector.

Focus:
- TCP/UDP flow grouping
- Best-effort TCP payload reassembly
- HTTP request/response parsing
- DNS query/response extraction
- TLS ClientHello SNI extraction (best-effort, no decryption)
- JSON block recovery
- Benign artifact decoding (URL/base64/hex heuristics)
- JSON report export

Note:
This analyzes what is present in the capture. Encrypted content cannot be
recovered without lawful decryption keys/session secrets.
"""

import argparse
import base64
import binascii
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote_plus

try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, Raw, TCP, UDP, rdpcap
except ImportError:
    print("[!] scapy is not installed. Run: pip install scapy")
    sys.exit(1)


DEFAULT_KEYWORDS = [
    b"password",
    b"passwd",
    b"token",
    b"auth",
    b"session",
    b"bearer",
    b"cookie",
    b"secret",
    b"api",
    b"key",
    b"reward",
    b"gift",
    b"voucher",
    b"coupon",
    b"login",
    b"admin",
]


HTTP_METHODS = (
    "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT "
)


def safe_decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return data.decode("utf-8", errors="ignore")


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return printable / max(1, len(s))


def is_probably_text(data: bytes) -> bool:
    if not data:
        return False
    # A small amount of NUL bytes usually means binary; still keep tolerant.
    if data.count(b"\x00") > len(data) // 20:
        return False
    text = safe_decode(data)
    return printable_ratio(text) >= 0.70


def canonical_flow_key(pkt):
    """
    Stable bidirectional key:
      ((ip_a, port_a), (ip_b, port_b), proto)
    Direction is returned separately.
    """
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        return None, None

    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        proto = "TCP"
    elif pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        proto = "UDP"
    else:
        return None, None

    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (a, b, proto), "a->b"
    return (b, a, proto), "b->a"


def reassemble_chunks(chunks):
    """
    Best-effort ordering by sequence/packet index.
    """
    if not chunks:
        return b""

    chunks = sorted(chunks, key=lambda x: (x[0], x[1]))
    out = bytearray()
    seen = set()

    for seq, idx, data in chunks:
        key = (seq, idx, len(data))
        if key in seen:
            continue
        seen.add(key)
        if data:
            out.extend(data)

    return bytes(out)


def extract_json_blocks(text: str):
    """
    Balanced-brace extraction for JSON-like blocks.
    More reliable than regex for nested braces.
    """
    blocks = []
    start = None
    depth = 0
    in_string = False
    escape = False

    for i, ch in enumerate(text):
        if start is None:
            if ch == "{":
                start = i
                depth = 1
                in_string = False
                escape = False
            continue

        if escape:
            escape = False
            continue

        if ch == "\\" and in_string:
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append(text[start:i + 1])
                start = None

    return blocks


def try_decode_base64(text: str):
    """
    Heuristic base64 extraction and decoding.
    """
    findings = []
    pattern = r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])'
    for m in re.finditer(pattern, text):
        token = m.group(1)
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = safe_decode(raw)
            if printable_ratio(decoded) >= 0.70:
                findings.append({
                    "token": token[:80],
                    "decoded_preview": decoded[:250],
                    "type": "base64",
                })
        except Exception:
            continue
    return findings


def try_decode_hex(text: str):
    findings = []
    pattern = r'(?<![A-Fa-f0-9])([A-Fa-f0-9]{32,})(?![A-Fa-f0-9])'
    for m in re.finditer(pattern, text):
        token = m.group(1)
        if len(token) % 2 != 0:
            continue
        try:
            raw = binascii.unhexlify(token)
            decoded = safe_decode(raw)
            if printable_ratio(decoded) >= 0.70:
                findings.append({
                    "token": token[:80],
                    "decoded_preview": decoded[:250],
                    "type": "hex",
                })
        except Exception:
            continue
    return findings


def extract_urls(text: str):
    # Conservative URL matcher.
    pattern = r'(?i)\b(?:https?|ftp)://[^\s\'"<>]+'
    return list(dict.fromkeys(re.findall(pattern, text)))


def extract_emails(text: str):
    pattern = r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
    return list(dict.fromkeys(re.findall(pattern, text)))


def parse_http(text: str):
    lines = text.splitlines()
    if not lines:
        return None

    first = lines[0].strip()
    if not (first.startswith(HTTP_METHODS) or first.startswith("HTTP/")):
        return None

    header_part, _, body = text.partition("\r\n\r\n")
    if not body:
        header_part, _, body = text.partition("\n\n")

    headers = {}
    header_lines = header_part.splitlines()
    if not header_lines:
        return None

    first_line = header_lines[0].strip()
    for line in header_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return {
        "first_line": first_line,
        "headers": headers,
        "body_preview": body[:400],
    }


def parse_dns(pkt):
    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return None

    dns = pkt[DNS]
    out = {
        "qr": int(getattr(dns, "qr", 0)),
        "id": int(getattr(dns, "id", 0)),
        "queries": [],
        "answers": [],
    }

    qd = getattr(dns, "qd", None)
    an = getattr(dns, "an", None)

    if qd:
        try:
            qcount = int(getattr(dns, "qdcount", 1))
        except Exception:
            qcount = 1
        cur = qd
        for _ in range(qcount):
            if not cur:
                break
            try:
                out["queries"].append({
                    "name": cur.qname.decode("utf-8", errors="ignore").rstrip("."),
                    "type": int(cur.qtype),
                })
            except Exception:
                pass
            cur = cur.payload if isinstance(cur.payload, DNSQR) else None

    if an:
        try:
            acount = int(getattr(dns, "ancount", 1))
        except Exception:
            acount = 1
        cur = an
        for _ in range(acount):
            if not cur:
                break
            try:
                rr = {
                    "name": cur.rrname.decode("utf-8", errors="ignore").rstrip("."),
                    "type": int(cur.type),
                    "ttl": int(getattr(cur, "ttl", 0)),
                }
                if hasattr(cur, "rdata"):
                    rdata = cur.rdata
                    if isinstance(rdata, bytes):
                        rr["rdata"] = safe_decode(rdata)
                    else:
                        rr["rdata"] = str(rdata)
                out["answers"].append(rr)
            except Exception:
                pass
            cur = cur.payload if isinstance(cur.payload, DNSRR) else None

    return out


def parse_tls_sni(payload: bytes):
    """
    Best-effort TLS ClientHello SNI extraction from raw bytes.
    Works only when the ClientHello is present in a single payload chunk.
    """
    try:
        if len(payload) < 5:
            return None
        content_type = payload[0]
        if content_type != 22:  # handshake
            return None

        # TLS record header: 5 bytes
        rec_len = int.from_bytes(payload[3:5], "big")
        record = payload[:5 + rec_len] if len(payload) >= 5 + rec_len else payload

        if len(record) < 9:
            return None

        idx = 5
        hs_type = record[idx]
        if hs_type != 1:  # ClientHello
            return None

        idx += 1
        hs_len = int.from_bytes(record[idx:idx + 3], "big")
        idx += 3

        if idx + 34 > len(record):
            return None

        # client_version (2) + random (32)
        idx += 2 + 32

        if idx >= len(record):
            return None

        sid_len = record[idx]
        idx += 1 + sid_len

        if idx + 2 > len(record):
            return None

        cs_len = int.from_bytes(record[idx:idx + 2], "big")
        idx += 2 + cs_len

        if idx >= len(record):
            return None

        comp_len = record[idx]
        idx += 1 + comp_len

        if idx + 2 > len(record):
            return None

        ext_total = int.from_bytes(record[idx:idx + 2], "big")
        idx += 2
        end = min(len(record), idx + ext_total)

        while idx + 4 <= end:
            ext_type = int.from_bytes(record[idx:idx + 2], "big")
            ext_len = int.from_bytes(record[idx + 2:idx + 4], "big")
            idx += 4
            ext_data = record[idx:idx + ext_len]
            idx += ext_len

            if ext_type == 0 and len(ext_data) >= 5:
                # ServerNameList
                p = 2
                while p + 3 <= len(ext_data):
                    name_type = ext_data[p]
                    name_len = int.from_bytes(ext_data[p + 1:p + 3], "big")
                    p += 3
                    name = ext_data[p:p + name_len].decode("utf-8", errors="ignore").strip()
                    p += name_len
                    if name_type == 0 and name:
                        return name
        return None
    except Exception:
        return None


def flow_identity(pkt):
    key, direction = canonical_flow_key(pkt)
    if key is None:
        return None, None
    return key, direction


def pretty_flow_name(flow_key):
    (a_ip, a_port), (b_ip, b_port), proto = flow_key
    return f"{a_ip}:{a_port} <-> {b_ip}:{b_port} ({proto})"


def score_keywords(raw: bytes, keywords):
    lowered = raw.lower()
    hits = [kw.decode("utf-8", errors="ignore") for kw in keywords if kw.lower() in lowered]
    return hits


def analyze_capture(pcap_path: str, keywords, show_all=False, max_preview=300, report_path=None):
    p = Path(pcap_path)
    if not p.exists():
        print(f"[!] File not found: {p}")
        return 1

    try:
        packets = rdpcap(str(p))
    except Exception as e:
        print(f"[!] Failed to read capture: {e}")
        return 1

    tcp_flows = defaultdict(lambda: {"a->b": [], "b->a": []})
    dns_events = []
    stats = Counter()

    for idx, pkt in enumerate(packets):
        stats["packets"] += 1

        if pkt.haslayer(TCP):
            stats["tcp"] += 1
            if pkt.haslayer(Raw):
                stats["tcp_raw"] += 1
                key, direction = flow_identity(pkt)
                if key is not None:
                    raw = bytes(pkt[Raw].load)
                    seq = int(pkt[TCP].seq)
                    tcp_flows[key][direction].append((seq, idx, raw))

        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            stats["dns"] += 1
            dns = parse_dns(pkt)
            if dns:
                dns_events.append(dns)

    flow_reports = []
    matched_flows = 0
    extracted_json = 0

    for flow_key, dirs in tcp_flows.items():
        for direction, chunks in dirs.items():
            if not chunks:
                continue

            payload = reassemble_chunks(chunks)
            text = safe_decode(payload)
            kw_hits = score_keywords(payload, keywords)
            http = parse_http(text)
            sni = parse_tls_sni(payload)
            urls = extract_urls(text)
            emails = extract_emails(text)
            json_blocks = extract_json_blocks(text)
            b64_hits = try_decode_base64(text)
            hex_hits = try_decode_hex(text)

            interesting = bool(
                kw_hits or http or sni or urls or emails or json_blocks or b64_hits or hex_hits
            )

            if not interesting and not show_all:
                continue

            matched_flows += 1
            flow_name = pretty_flow_name(flow_key)
            print("\n" + "=" * 100)
            print(f"[FLOW] {flow_name}")
            print(f"[DIR ] {direction}")
            print(f"[SIZE] {len(payload)} bytes | chunks={len(chunks)}")
            print("=" * 100)

            if kw_hits:
                print(f"[KW  ] hits: {', '.join(kw_hits)}")

            if sni:
                print(f"[TLS ] SNI: {sni}")

            if http:
                print(f"[HTTP] {http['first_line']}")
                for hk in ("host", "user-agent", "content-type", "authorization", "cookie"):
                    if hk in http["headers"]:
                        print(f"       {hk}: {http['headers'][hk]}")
                if http["body_preview"].strip():
                    print(f"[BODY] {http['body_preview'][:max_preview]}")

            if urls:
                print("[URL ]")
                for u in urls[:10]:
                    print(f"       - {u}")

            if emails:
                print("[MAIL]")
                for e in emails[:10]:
                    print(f"       - {e}")

            if json_blocks:
                for n, block in enumerate(json_blocks, start=1):
                    try:
                        parsed = json.loads(block)
                        extracted_json += 1
                        print(f"[JSON] block #{n}")
                        print(json.dumps(parsed, indent=4, ensure_ascii=False))
                    except Exception:
                        snippet = block[:max_preview]
                        print(f"[JSON] fragment #{n}")
                        print(snippet + (" ... [TRUNCATED]" if len(block) > max_preview else ""))

            if b64_hits:
                print("[B64 ]")
                for item in b64_hits[:5]:
                    print(f"       token={item['token']}")
                    print(f"       decoded={item['decoded_preview']}")

            if hex_hits:
                print("[HEX ]")
                for item in hex_hits[:5]:
                    print(f"       token={item['token']}")
                    print(f"       decoded={item['decoded_preview']}")

            flow_reports.append({
                "flow": flow_name,
                "direction": direction,
                "bytes": len(payload),
                "keyword_hits": kw_hits,
                "tls_sni": sni,
                "http": http,
                "urls": urls[:50],
                "emails": emails[:50],
                "json_blocks_count": len(json_blocks),
                "base64_hits_count": len(b64_hits),
                "hex_hits_count": len(hex_hits),
            })

    print("\n" + "-" * 100)
    print("[SUMMARY]")
    print(f"Packets        : {stats['packets']}")
    print(f"TCP packets    : {stats['tcp']}")
    print(f"TCP raw packets: {stats['tcp_raw']}")
    print(f"DNS packets    : {stats['dns']}")
    print(f"Interesting flows: {matched_flows}")
    print(f"JSON extracted : {extracted_json}")
    print("-" * 100)

    report = {
        "file": str(p.resolve()),
        "stats": dict(stats),
        "interesting_flows": flow_reports,
        "dns_events": dns_events,
    }

    if report_path:
        out = Path(report_path)
    else:
        out = p.with_suffix(p.suffix + ".deep_report.json")

    try:
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Report saved to: {out}")
    except Exception as e:
        print(f"[!] Could not save report: {e}")

    return 0


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Deep PCAP forensic inspector"
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="game_traffic.pcap",
        help="Path to the pcap/pcapng file",
    )
    parser.add_argument(
        "-k",
        "--keyword",
        action="append",
        default=[],
        help="Extra keyword filter; can be repeated",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Print all reconstructed flows, not only interesting ones",
    )
    parser.add_argument(
        "--preview",
        type=int,
        default=300,
        help="Max preview chars for bodies/fragments",
    )
    parser.add_argument(
        "--report",
        default="",
        help="Custom output path for JSON report",
    )
    return parser


def main():
    args = build_arg_parser().parse_args()
    custom_keywords = [k.encode("utf-8", errors="ignore") for k in args.keyword] if args.keyword else DEFAULT_KEYWORDS

    try:
        code = analyze_capture(
            pcap_path=args.pcap,
            keywords=custom_keywords,
            show_all=args.all,
            max_preview=max(50, int(args.preview)),
            report_path=args.report or None,
        )
        sys.exit(code)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
