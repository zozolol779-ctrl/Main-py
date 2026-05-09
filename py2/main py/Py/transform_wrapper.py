#!/usr/bin/env python3
import sys, subprocess, os, json

if len(sys.argv) < 2:
    sys.stderr.write("Usage: transform_wrapper.py <entity-value>\n")
    sys.exit(2)
value = sys.argv[1]

PY = sys.executable
ENRICH = os.path.join(os.path.dirname(__file__), 'graph_enricher.py')
if not os.path.exists(ENRICH):
    ENRICH = r"C:\Users\mido7\AppData\Roaming\maltego\v4.10.1\config\Maltego\Machines\graph_enricher.py"
CONVERT = os.path.join(os.path.dirname(__file__), 'graph_enricher_maltego.py')
TMP_JSON = r"C:\temp\wrapper_json.json"
LOG_STDOUT = r"C:\temp\wrapper_stdout.log"
LOG_STDERR = r"C:\temp\wrapper_stderr.log"

# run enricher
p = subprocess.run([PY, ENRICH, "--entity", value, "--type", "ip", "--config",
                   r"C:\Users\mido7\AppData\Roaming\maltego\v4.10.1\config\Maltego\Machines\config.json",
                   "--log", r"C:\Users\mido\A\AppData\Roaming\maltego\v4.10.1\config\Maltego\Machines\graph_enricher.log",
                   "--verbose"], capture_output=True, text=True, timeout=180)

open(LOG_STDOUT,'w',encoding='utf-8').write(p.stdout)
open(LOG_STDERR,'w',encoding='utf-8').write(p.stderr)

if p.returncode != 0 or not p.stdout.strip():
    sys.stderr.write("Enricher failed or produced no stdout. See logs.\n")
    sys.exit(p.returncode or 4)

with open(TMP_JSON,'w',encoding='utf-8') as f:
    f.write(p.stdout)

# run converter
q = subprocess.run([PY, CONVERT, "--input", TMP_JSON], capture_output=True, text=True)
open(LOG_STDOUT,'a',encoding='utf-8').write("\n=== CONVERT STDOUT ===\n"+q.stdout)
open(LOG_STDERR,'a',encoding='utf-8').write("\n=== CONVERT STDERR ===\n"+q.stderr)

if q.returncode != 0:
    sys.stderr.write("Converter failed. See logs.\n")
    sys.exit(q.returncode)

sys.stdout.write(q.stdout)
'@ | Set-Content -Path (Join-Path $dest 'transform_wrapper.py') -Encoding UTF8 -Force

# graph_enricher_maltego.py (clean)
@'
#!/usr/bin/env python3
import sys, json
from html import escape

ENTITY_TEMPLATES = {
    'ipv4': 'maltego.IPv4Address',
    'domain': 'maltego.DNSName',
    'asn': 'maltego.ASNumber',
    'org': 'maltego.Organization',
    'location': 'maltego.Location',
    'service': 'maltego.Service',
    'port': 'maltego.Port',
    'malicious': 'maltego.MaliciousIP',
}

def field_xml(name, value, display=None):
    name = escape(name)
    display = escape(display) if display else name
    value = escape(str(value))
    return f'<Field Name="{name}" DisplayName="{display}">{value}</Field>'

def entity_xml(ent_type, value, fields=None):
    value = escape(str(value))
    out = [f'<Entity Type="{ent_type}">', f'  <Value>{value}</Value>']
    if fields:
        out.append('  <AdditionalFields>')
        for k,v in fields.items():
            vs = v if isinstance(v,str) else str(v)
            if len(vs)>2000: vs = vs[:2000]
            out.append('    ' + field_xml(k,vs))
        out.append('  </AdditionalFields>')
    out.append('</Entity>')
    return "\\n".join(out)

def render_maltego_message(entities):
    header = '<MaltegoMessage>\\n  <MaltegoTransformResponseMessage>\\n    <Entities>'
    footer = '    </Entities>\\n  </MaltegoTransformResponseMessage>\\n</MaltegoMessage>'
    parts=[header]
    for e in entities:
        for line in e.split('\\n'):
            parts.append('      ' + line)
    parts.append(footer)
    return '\\n'.join(parts)

def build_entities_from_json(data):
    entities=[]
    ip = data.get('ip') or data.get('query') or data.get('address')
    if ip: entities.append(entity_xml(ENTITY_TEMPLATES['ipv4'], ip, {'source': 'graph_enricher'}))
    ipinfo = data.get('ipinfo') or {}
    if ipinfo:
        loc = ', '.join(x for x in (ipinfo.get('city'), ipinfo.get('region'), ipinfo.get('country')) if x)
        if loc: entities.append(entity_xml(ENTITY_TEMPLATES['location'], loc, {'provider':'ipinfo','loc_raw':ipinfo.get('loc','')}))
        if ipinfo.get('org'): entities.append(entity_xml(ENTITY_TEMPLATES['org'], ipinfo.get('org'), {'provider':'ipinfo'}))
        if ipinfo.get('asn'): entities.append(entity_xml(ENTITY_TEMPLATES['asn'], ipinfo.get('asn'), {'provider':'ipinfo'}))
    shodan = data.get('shodan') or {}
    services = shodan.get('data') if isinstance(shodan.get('data'), list) else shodan.get('services')
    if services:
        for svc in services:
            port = svc.get('port') or svc.get('portnum')
            banner = svc.get('banner') or svc.get('product') or svc.get('data')
            proto = svc.get('transport') or svc.get('protocol')
            s_fields = {'provider':'shodan'}
            if banner: s_fields['banner'] = str(banner)[:1000]
            if proto: s_fields['protocol'] = proto
            if port:
                entities.append(entity_xml(ENTITY_TEMPLATES['port'], port, s_fields))
                svc_val = f"{ip or 'unknown'}:{port}"
                entities.append(entity_xml(ENTITY_TEMPLATES['service'], svc_val, s_fields))
    vt = data.get('virustotal') or {}
    domains = vt.get('domains') or vt.get('related_domains') or []
    for d in domains: entities.append(entity_xml(ENTITY_TEMPLATES['domain'], d, {'provider':'virustotal'}))
    scans = vt.get('scans') or vt.get('results')
    if isinstance(scans, dict):
        positives = sum(1 for r in scans.values() if isinstance(r,dict) and r.get('detected'))
        total = len(scans)
        entities.append(entity_xml('maltego.Note', f'VT detection {positives}/{total}', {'provider':'virustotal'}))
    abuse = data.get('abuseipdb') or {}
    if abuse:
        score = abuse.get('abuseConfidenceScore') or abuse.get('score')
        categories = abuse.get('categories')
        fields={'provider':'AbuseIPDB'}
        if score is not None: fields['score']=score
        if categories: fields['categories']=','.join(map(str,categories))
        entities.append(entity_xml(ENTITY_TEMPLATES['malicious'], ip or 'unknown', fields))
    cert = data.get('cert') or data.get('certificate') or {}
    if cert:
        subj = cert.get('subject') or cert.get('subject_dn')
        issuer = cert.get('issuer')
        valid_to = cert.get('valid_to') or cert.get('not_after')
        note = ' | '.join(x for x in (f'Subject:{subj}' if subj else None, f'Issuer:{issuer}' if issuer else None, f'ValidTo:{valid_to}' if valid_to else None) if x)
        if note: entities.append(entity_xml('maltego.Note', note, {'provider':'certificate'}))
    try: raw = json.dumps(data, ensure_ascii=False)
    except: raw = str(data)
    entities.append(entity_xml('maltego.Note','Raw JSON snapshot',{'raw':raw[:2000]}))
    return entities

def main():
    import argparse
    p = argparse.ArgumentParser(description='Convert graph_enricher JSON -> Maltego XML')
    p.add_argument('--input','-i',help='JSON input file (default stdin)')
    args = p.parse_args()
    try:
        if args.input:
            with open(args.input,'r',encoding='utf-8') as f: data=json.load(f)
        else:
            data=json.load(sys.stdin)
    except Exception as e:
        sys.stderr.write(f'Failed to read JSON: {e}\\n'); sys.exit(2)
    entities = build_entities_from_json(data)
    maltego_xml = render_maltego_message(entities)
    sys.stdout.write(maltego_xml)

if __name__ == '__main__': main()