#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║      Salem Unified Radar — رادار جنائي موحد            ║
║      PCAP + JSON  |  DNS  |  Ports  |  Protocols        ║
╚══════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import csv
import logging
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterator

# ══════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("salem_radar")

# ══════════════════════════════════════════════════════
#  KNOWN PORTS — قاموس البورتات المعروفة
# ══════════════════════════════════════════════════════
KNOWN_PORTS = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    123:  "NTP",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "Syslog",
    587:  "SMTP-TLS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1723: "PPTP-VPN",
    1947: "HASP/Sentinel",   # ← المفتاح بتاعك
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",      # ← مشبوه جداً
    4500: "IPSec-VPN",
    5222: "XMPP",
    5900: "VNC",
    6881: "BitTorrent",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9001: "Tor",             # ← مشبوه
    9050: "Tor-SOCKS",       # ← مشبوه
}

# بورتات مشبوهة تستحق تحذير خاص
SUSPICIOUS_PORTS = {4444, 9001, 9050, 1080, 6667, 31337}

# ══════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════
@dataclass
class Config:
    scan_dir:  str = "/storage/emulated/0/Download/"
    out_json:  str = "/storage/emulated/0/Download/radar_report.json"
    out_csv:   str = "/storage/emulated/0/Download/radar_ports.csv"
    target:    str = "192.168.1.46"
    my_server: str = "192.168.1.59"
    hasp_port: int = 1947
    top_n:     int = 10

# ══════════════════════════════════════════════════════
#  RESULT — نتيجة كل ملف
# ══════════════════════════════════════════════════════
@dataclass
class FileResult:
    file_name:    str
    file_type:    str
    json_format:  str     = ""
    total_pkts:   int     = 0
    server_talks: int     = 0

    # البورتات: {port_number: count}
    port_counter: Counter = field(default_factory=Counter)

    # الاتصالات: {"IP (PROTO/PORT/name)": count}
    connections:  Counter = field(default_factory=Counter)

    # DNS queries
    dns_queries:  set     = field(default_factory=set)

    # External IPs
    external_ips: Counter = field(default_factory=Counter)

    @property
    def is_suspicious(self) -> bool:
        if self.external_ips:
            return True
        if any(p in SUSPICIOUS_PORTS for p in self.port_counter):
            return True
        return False

# ══════════════════════════════════════════════════════
#  ANDROID PATH RESOLVER
# ══════════════════════════════════════════════════════
def resolve_dir(path: str) -> str:
    alts = [
        path,
        path.replace("/storage/emulated/0/", "/sdcard/"),
        path.replace("/sdcard/", "/storage/emulated/0/"),
    ]
    for p in alts:
        if os.path.isdir(p):
            return p
    raise FileNotFoundError(f"المجلد غير موجود: {path}")

# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════
def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True

def port_label(port: int) -> str:
    """يرجع اسم البورت لو معروف."""
    name = KNOWN_PORTS.get(port, "")
    return f"{port}/{name}" if name else str(port)

def flag_port(port: int) -> str:
    """يرجع إيموجي مناسب للبورت."""
    if port in SUSPICIOUS_PORTS:
        return "🚨"
    if port == 1947:
        return "🔑"
    if port in (443, 8443):
        return "🔒"
    if port in (80, 8080, 8888):
        return "🌐"
    if port == 53:
        return "📡"
    if port == 22:
        return "🖥️"
    if port == 3389:
        return "🖥️"
    return "🔹"

# ══════════════════════════════════════════════════════
#  JSON PARSER — Streaming (Array + NDJSON)
# ══════════════════════════════════════════════════════
def _detect_json_format(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            ch = f.read(1)
            if not ch:
                return "ndjson"
            if not ch.isspace():
                return "array" if ch == '[' else "ndjson"

def _parse_array(f) -> Iterator[dict]:
    buf = ""; depth = 0; in_str = False; escape = False
    while True:
        c = f.read(1)
        if not c: break
        if in_str:
            buf += c
            if escape: escape = False
            elif c == "\\": escape = True
            elif c == '"': in_str = False
            continue
        if c == '"': in_str = True; buf += c
        elif c == '{': depth += 1; buf += c
        elif c == '}':
            depth -= 1; buf += c
            if depth == 0:
                try: yield json.loads(buf)
                except json.JSONDecodeError: pass
                buf = ""
        elif depth > 0: buf += c

def _parse_ndjson(f) -> Iterator[dict]:
    for line in f:
        line = line.strip()
        if not line: continue
        try: yield json.loads(line)
        except json.JSONDecodeError: continue

def iter_json_packets(path: str):
    fmt = _detect_json_format(path)
    def _gen():
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            if fmt == "array":
                while True:
                    ch = f.read(1)
                    if not ch: return
                    if ch == '[': break
                yield from _parse_array(f)
            else:
                yield from _parse_ndjson(f)
    return fmt, _gen()

# ══════════════════════════════════════════════════════
#  PCAP ANALYSIS ENGINE
# ══════════════════════════════════════════════════════
def analyze_pcap_file(file_path: str, file_name: str, cfg: Config) -> FileResult:
    from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR

    result = FileResult(file_name=file_name, file_type="pcap")

    with PcapReader(file_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst

            if cfg.target not in (src, dst):
                continue

            result.total_pkts += 1
            remote = dst if src == cfg.target else src

            # ── بروتوكول وبورت ──────────────────────
            proto = "Other"
            sport = dport = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # البورت الخاص بالـ remote (مش بتاع الجهاز 46)
            remote_port = dport if src == cfg.target else sport
            svc = KNOWN_PORTS.get(remote_port, "")
            label = f"{port_label(remote_port)}" + (f" [{svc}]" if svc else "")

            result.port_counter[remote_port] += 1
            result.connections[f"{remote}  {proto}/{label}"] += 1

            # ── سيرفر ───────────────────────────────
            if remote == cfg.my_server:
                result.server_talks += 1

            # ── External IP ─────────────────────────
            if remote and not is_private(remote):
                result.external_ips[remote] += 1

            # ── DNS queries ─────────────────────────
            if pkt.haslayer(DNSQR):
                try:
                    q = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    if q:
                        result.dns_queries.add(q)
                except Exception:
                    pass

    return result

# ══════════════════════════════════════════════════════
#  JSON ANALYSIS ENGINE
# ══════════════════════════════════════════════════════
PORT_KEYS = ("port", "dport", "dst_port", "sport", "src_port")

def analyze_json_file(file_path: str, file_name: str, cfg: Config) -> FileResult:
    fmt, packets = iter_json_packets(file_path)
    result = FileResult(file_name=file_name, file_type="json", json_format=fmt)

    for pkt in packets:
        src = str(pkt.get("src_ip") or pkt.get("src") or pkt.get("source") or "")
        dst = str(pkt.get("dst_ip") or pkt.get("dst") or pkt.get("destination") or "")

        if cfg.target not in (src, dst):
            continue

        result.total_pkts += 1
        remote = dst if src == cfg.target else src

        if remote == cfg.my_server:
            result.server_talks += 1

        if remote and not is_private(remote):
            result.external_ips[remote] += 1

        # استخراج البورت
        for k in PORT_KEYS:
            v = pkt.get(k)
            if v:
                try:
                    port = int(v)
                    svc  = KNOWN_PORTS.get(port, "")
                    label = port_label(port) + (f" [{svc}]" if svc else "")
                    result.port_counter[port] += 1
                    result.connections[f"{remote}  ?/{label}"] += 1
                except (ValueError, TypeError):
                    pass
                break

        # DNS من الـ JSON لو موجود
        for k in ("dns", "dns_query", "hostname", "host"):
            v = pkt.get(k)
            if v:
                result.dns_queries.add(str(v).rstrip("."))
                break

    return result

# ══════════════════════════════════════════════════════
#  PRINT PER-FILE REPORT
# ══════════════════════════════════════════════════════
def print_file_report(r: FileResult, cfg: Config) -> None:
    sep = "─" * 54

    print(f"\n{sep}")
    fmt_tag = f" [{r.json_format}]" if r.json_format else ""
    print(f"📄 {r.file_name}{fmt_tag}  —  {r.total_pkts:,} حزمة")
    print(sep)

    # ── البورتات ──────────────────────────────────────
    if r.port_counter:
        print("🔌 البورتات المرصودة:")
        for port, cnt in r.port_counter.most_common(cfg.top_n):
            icon  = flag_port(port)
            name  = KNOWN_PORTS.get(port, "Unknown")
            warn  = "  ⚠️  مشبوه!" if port in SUSPICIOUS_PORTS else ""
            print(f"   {icon} {port:<6} {name:<18} {cnt:>5} حزمة{warn}")
    else:
        print("   ℹ️  لا توجد بورتات مرصودة.")

    # ── الاتصالات ─────────────────────────────────────
    if r.connections:
        print("\n🔗 أبرز الاتصالات:")
        for conn, cnt in r.connections.most_common(cfg.top_n):
            print(f"   {'🔴' if not is_private(conn.split()[0]) else '🔵'} {conn:<45} {cnt:>5} حزمة")

    # ── DNS ───────────────────────────────────────────
    if r.dns_queries:
        print(f"\n📡 DNS Queries ({len(r.dns_queries)} موقع):")
        for site in sorted(r.dns_queries)[:cfg.top_n]:
            print(f"   🌍 {site}")
        if len(r.dns_queries) > cfg.top_n:
            print(f"   ... و {len(r.dns_queries) - cfg.top_n} موقع إضافي")
    else:
        print("\n   ℹ️  لا توجد DNS queries.")

    # ── External IPs ──────────────────────────────────
    if r.external_ips:
        print(f"\n⚠️  External IPs:")
        for ip, cnt in r.external_ips.most_common(5):
            print(f"   🌐 {ip:<22} {cnt:>5} حزمة")

# ══════════════════════════════════════════════════════
#  PRINT FINAL SUMMARY
# ══════════════════════════════════════════════════════
def print_final_summary(
    results:      list,
    combined_ext: Counter,
    combined_pts: Counter,
    combined_dns: set,
    cfg:          Config,
    pcap_count:   int,
    json_count:   int,
) -> None:
    sep = "═" * 54
    suspicious = [r for r in results if r.is_suspicious]
    total_pkts = sum(r.total_pkts for r in results)

    print(f"\n{sep}")
    print("📊  التقرير النهائي الموحد — ملخص شامل")
    print(sep)
    print(f"   الملفات المفحوصة   : {len(results)}  ({pcap_count} pcap / {json_count} json)")
    print(f"   إجمالي حزم الجهاز  : {total_pkts:,}")

    # ── أبرز البورتات الكلية ──────────────────────────
    print(f"\n   🔌 أبرز البورتات عبر كل الملفات:")
    for port, cnt in combined_pts.most_common(cfg.top_n):
        icon = flag_port(port)
        name = KNOWN_PORTS.get(port, "Unknown")
        warn = "  ⚠️ مشبوه!" if port in SUSPICIOUS_PORTS else ""
        print(f"      {icon} {port:<6} {name:<18} {cnt:>6} حزمة{warn}")

    # ── DNS كلية ──────────────────────────────────────
    if combined_dns:
        print(f"\n   📡 DNS Queries الكلية: {len(combined_dns)} موقع مختلف")
        for site in sorted(combined_dns)[:cfg.top_n]:
            print(f"      🌍 {site}")
        if len(combined_dns) > cfg.top_n:
            print(f"      ... و {len(combined_dns) - cfg.top_n} موقع إضافي")

    # ── External IPs ──────────────────────────────────
    if not combined_ext:
        print(f"\n   🛡️  لا يوجد اتصال خارجي — الجهاز نظيف!")
    else:
        print(f"\n   ⚠️  ملفات مشبوهة ({len(suspicious)}):")
        for r in suspicious:
            tag = "📡 pcap" if r.file_type == "pcap" else "📋 json"
            print(f"      {tag}  {r.file_name}")

        print(f"\n   🌐 أبرز External IPs مجمعة:")
        for ip, cnt in combined_ext.most_common(cfg.top_n):
            print(f"      🎯 {ip:<24} {cnt:>6} حزمة")

    print(sep)

# ══════════════════════════════════════════════════════
#  SAVE REPORTS
# ══════════════════════════════════════════════════════
def save_reports(
    results:      list,
    combined_ext: Counter,
    combined_pts: Counter,
    combined_dns: set,
    cfg:          Config,
) -> None:
    total_pkts = sum(r.total_pkts for r in results)

    # ── JSON ──────────────────────────────────────────
    data = {
        "target":        cfg.target,
        "my_server":     cfg.my_server,
        "total_packets": total_pkts,
        "external_ips":  dict(combined_ext),
        "top_ports": {
            str(p): {"count": c, "service": KNOWN_PORTS.get(p, "Unknown"),
                     "suspicious": p in SUSPICIOUS_PORTS}
            for p, c in combined_pts.most_common()
        },
        "dns_queries": sorted(combined_dns),
        "files": [
            {
                "name":         r.file_name,
                "type":         r.file_type,
                "json_format":  r.json_format or None,
                "packets":      r.total_pkts,
                "server_talks": r.server_talks,
                "suspicious":   r.is_suspicious,
                "ports":        {
                    str(p): {"count": c, "service": KNOWN_PORTS.get(p, "Unknown")}
                    for p, c in r.port_counter.most_common()
                },
                "external_ips": dict(r.external_ips.most_common()),
                "dns_queries":  sorted(r.dns_queries),
            }
            for r in results
        ],
    }
    try:
        with open(cfg.out_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"✅ JSON saved  → {cfg.out_json}")
    except OSError as e:
        log.warning("JSON save failed: %s", e)

    # ── CSV للبورتات ──────────────────────────────────
    try:
        with open(cfg.out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["port", "service", "total_count", "suspicious"])
            for port, cnt in combined_pts.most_common():
                writer.writerow([
                    port,
                    KNOWN_PORTS.get(port, "Unknown"),
                    cnt,
                    "YES" if port in SUSPICIOUS_PORTS else "NO",
                ])
        print(f"✅ CSV saved   → {cfg.out_csv}")
    except OSError as e:
        log.warning("CSV save failed: %s", e)

# ══════════════════════════════════════════════════════
#  MAIN SCANNER
# ══════════════════════════════════════════════════════
def run_radar(cfg: Config) -> None:
    print("\n" + "═"*54)
    print("🚀  Salem Forensics Radar — رادار جنائي موحد")
    print("    PCAP + JSON  |  Ports  |  DNS  |  Protocols")
    print("═"*54)

    try:
        scan_dir = resolve_dir(cfg.scan_dir)
    except FileNotFoundError as e:
        print(f"❌ {e}")
        return

    all_files  = os.listdir(scan_dir)
    pcap_files = sorted(f for f in all_files if f.lower().endswith(('.pcap', '.pcapng')))
    json_files = sorted(
        f for f in all_files
        if f.lower().endswith('.json') and not f.startswith("radar_")
    )

    total_files = len(pcap_files) + len(json_files)
    if total_files == 0:
        print(f"❌ لم أجد أي ملفات PCAP أو JSON في:\n   {scan_dir}")
        return

    print(f"📂 تم العثور على: {len(pcap_files)} PCAP + {len(json_files)} JSON")
    print(f"🎯 الجهاز المستهدف : {cfg.target}")
    print(f"🖥️  السيرفر         : {cfg.my_server}\n")

    all_results: list = []

    # ── فحص PCAP ────────────────────────────────────
    if pcap_files:
        print("══ ملفات PCAP " + "═"*38)
        for file_name in pcap_files:
            file_path = os.path.join(scan_dir, file_name)
            print(f"⚙️  جاري فحص: {file_name}...", flush=True)
            try:
                r = analyze_pcap_file(file_path, file_name, cfg)
                all_results.append(r)
                print_file_report(r, cfg)
            except Exception as e:
                print(f"⚠️  خطأ في {file_name}: {e}")

    # ── فحص JSON ────────────────────────────────────
    if json_files:
        print("\n══ ملفات JSON " + "═"*38)
        for file_name in json_files:
            file_path = os.path.join(scan_dir, file_name)
            print(f"⚙️  جاري فحص: {file_name}...", flush=True)
            try:
                r = analyze_json_file(file_path, file_name, cfg)
                all_results.append(r)
                print_file_report(r, cfg)
            except Exception as e:
                print(f"⚠️  خطأ في {file_name}: {e}")

    # ── إحصائيات مجمعة ──────────────────────────────
    combined_ext = Counter()
    combined_pts = Counter()
    combined_dns = set()
    for r in all_results:
        combined_ext.update(r.external_ips)
        combined_pts.update(r.port_counter)
        combined_dns.update(r.dns_queries)

    # ── طباعة + حفظ ─────────────────────────────────
    print_final_summary(
        all_results, combined_ext, combined_pts, combined_dns, cfg,
        len(pcap_files), len(json_files),
    )
    print()
    save_reports(all_results, combined_ext, combined_pts, combined_dns, cfg)
    print()

# ══════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════
def main() -> int:
    print("⏳ جاري تحميل أدوات التحليل... يرجى الانتظار...")

    cfg = Config()
    if len(sys.argv) > 1: cfg.scan_dir  = sys.argv[1]
    if len(sys.argv) > 2: cfg.target    = sys.argv[2]
    if len(sys.argv) > 3: cfg.my_server = sys.argv[3]

    try:
        run_radar(cfg)
    except KeyboardInterrupt:
        print("\n⛔ تم إيقاف الرادار.")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
