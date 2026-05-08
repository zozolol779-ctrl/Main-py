#!/usr/bin/env python3
import sys, json
import xml.etree.ElementTree as ET

def make_entity(type_name, value, weight=100):
    """Builds a Maltego entity XML node"""
    e = ET.Element("Entity", Type=type_name)
    v = ET.SubElement(e, "Value")
    v.text = str(value)
    w = ET.SubElement(e, "Weight")
    w.text = str(weight)
    return e

def json_to_maltego_entities(data):
    """Convert JSON dict into Maltego XML <MaltegoMessage>"""
    msg = ET.Element("MaltegoMessage")
    resp = ET.SubElement(msg, "MaltegoTransformResponseMessage")
    entities = ET.SubElement(resp, "Entities")

    # مثال: لو JSON فيه {"ips": [...], "domains": [...]}
    if "ips" in data:
        for ip in data["ips"]:
            entities.append(make_entity("maltego.IPv4Address", ip))

    if "domains" in data:
        for d in data["domains"]:
            entities.append(make_entity("maltego.Domain", d))

    if "hashes" in data:
        for h in data["hashes"]:
            entities.append(make_entity("maltego.Hash", h))

    return msg

def main():
    # -----------------------------
    # 1️⃣ Input
    # -----------------------------
    if "--input" in sys.argv:
        idx = sys.argv.index("--input") + 1
        infile = sys.argv[idx]
        with open(infile, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        # لو جالك input من STDIN (زي Maltego Transform)
        raw = sys.stdin.read().strip()
        data = json.loads(raw) if raw else {}

    # -----------------------------
    # 2️⃣ Build XML
    # -----------------------------
    msg = json_to_maltego_entities(data)

    # -----------------------------
    # 3️⃣ Output
    # -----------------------------
    sys.stdout.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    sys.stdout.write(ET.tostring(msg, encoding="unicode"))

if __name__ == "__main__":
    main()
