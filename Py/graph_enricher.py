#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-
"""
graph_enricher.py - Maltego-ready
- Queries configured services (ipinfo, shodan, abuseipdb, virustotal, ...)
- Converts results to Maltego Transform XML (stdout) when --maltego passed
- Otherwise can still write JSON output file (--out)
"""

from __future__ import annotations
import argparse
import json
import os
import re
import time
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from xml.sax.saxutils import escape

import requests

# --- helpers for config expansion ---
_env_pattern = re.compile(r'\$\{([^}]+)\}')

def expand_in_obj(obj):
    if isinstance(obj, dict):
        return {k: expand_in_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_in_obj(v) for v in obj]
    if isinstance(obj, str):
        def repl(m):
            name = m.group(1)
            val = os.environ.get(name)
            return "" if val is None else val
        return _env_pattern.sub(repl, obj)
    return obj

# --- HTTP with retries ---
def retry_request(session, method, url, headers=None, params=None, timeout=10, max_retries=3, backoff=1.6):
    attempt = 0
    while True:
        try:
            resp = session.request(method, url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 429 and attempt < max_retries:
                attempt += 1
                wait = backoff ** attempt
                logging.warning("429 from %s -> retry %d after %.1f s", url, attempt, wait)
                time.sleep(wait)
                continue
            return resp
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            if attempt < max_retries:
                attempt += 1
                wait = backoff ** attempt
                logging.warning("Transient error contacting %s: %s - retry %d after %.1f s", url, exc, attempt, wait)
                time.sleep(wait)
                continue
            raise

def build_url_from_template(template, value, value_type):
    if not template:
        return None
    qval = quote(value, safe='')
    return template.replace("{value}", qval).replace("{type}", value_type)

def call_service(session, service_name, service_cfg, value, value_type, timeout_seconds, retry_on_rate_limit):
    result = {"service": service_name, "success": False, "status_code": None, "url": None, "error": None, "raw": None}
    # choose template
    template = None
    if isinstance(service_cfg.get("templates"), dict):
        template = service_cfg["templates"].get(value_type) or service_cfg["templates"].get("any")
    if not template:
        template = service_cfg.get("template")
    if not template:
        result["error"] = "no_template_provided"
        return result
    url = build_url_from_template(template, value, value_type)
    result["url"] = url
    headers = {}
    params = {}
    auth = service_cfg.get("auth") or {}
    method = auth.get("method")
    api_key = auth.get("api_key") or ""
    if method == "header":
        header_name = auth.get("header_name", "api-key")
        headers[header_name] = api_key
    elif method == "query":
        key_name = auth.get("key_name", "api_key")
        params[key_name] = api_key
    try:
        max_retries = 3 if retry_on_rate_limit else 1
        resp = retry_request(session, "GET", url, headers=headers, params=params, timeout=timeout_seconds, max_retries=max_retries)
        result["status_code"] = resp.status_code
        # attempt to parse JSON
        try:
            result["raw"] = resp.json()
        except Exception:
            result["raw"] = resp.text[:32000]
        result["success"] = 200 <= resp.status_code < 300
        if not result["success"]:
            result["error"] = f"status_{resp.status_code}"
    except Exception as e:
        logging.exception("Exception while calling %s", service_name)
        result["error"] = str(e)
    return result

def enrich_entity(entity_value, entity_type, config):
    timeout_seconds = int(config.get("timeout_seconds", 10))
    max_workers = int(config.get("max_concurrent_requests", 4))
    retry_on_rate_limit = bool(config.get("retry_on_rate_limit", False))
    node_service_map = config.get("node_service_map", {})
    services_for_type = node_service_map.get(entity_type) or node_service_map.get("any", [])
    services_cfg = config.get("services", {})
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": f"graph-enricher/1.0"})
    with ThreadPoolExecutor(max_workers=max_workers) as exc:
        futures = {}
        for svc in services_for_type:
            svc_cfg = services_cfg.get(svc)
            if not svc_cfg:
                logging.debug("Service %s not configured, skipping", svc)
                continue
            futures[exc.submit(call_service, session, svc, svc_cfg, entity_value, entity_type, timeout_seconds, retry_on_rate_limit)] = svc
        for fut in as_completed(futures):
            svc_name = futures[fut]
            try:
                res = fut.result()
                results.append(res)
                logging.debug("Service %s finished: status=%s error=%s", svc_name, res.get("status_code"), res.get("error"))
            except Exception as e:
                logging.exception("Fatal error running service %s", svc_name)
                results.append({"service": svc_name, "success": False, "error": str(e)})
    return results

# --- Maltego XML building helpers ---
def maltego_entity_xml(entity_type: str, value: str, fields: dict | None = None) -> str:
    """Return one <Entity> XML block. Fields is dict of additional fields."""
    value_esc = escape(value or "")
    fields_xml = ""
    if fields:
        for k, v in fields.items():
            k_esc = escape(str(k))
            v_esc = escape("" if v is None else str(v))
            fields_xml += f'<Field Name="{k_esc}">{v_esc}</Field>'
    entity_xml = f'<Entity Type="{escape(entity_type)}"><Value>{value_esc}</Value><AdditionalFields>{fields_xml}</AdditionalFields></Entity>'
    return entity_xml

def build_maltego_response(results_list):
    """
    Convert results_list (list of service result dicts) into Maltego XML string.
    We try to produce sensible entity types for each service.
    """
    service_map = {r["service"]: r for r in results_list}
    entities = []

    # IPINFO -> Location, IPv4, Organization/ASN
    ipinfo = service_map.get("ipinfo")
    if ipinfo and ipinfo.get("success") and isinstance(ipinfo.get("raw"), dict):
        raw = ipinfo["raw"]
        city = raw.get("city")
        country = raw.get("country")
        loc = raw.get("loc", "")
        lat, lon = ("", "")
        if isinstance(loc, str) and "," in loc:
            lat, lon = loc.split(",", 1)
        # Location entity
        if city or country:
            entities.append(maltego_entity_xml("maltego.Location", f"{city or ''}, {country or ''}".strip(", "), {"latitude": lat, "longitude": lon, "city": city or "", "country": country or ""}))
        # IP entity
        ip_val = raw.get("ip")
        if ip_val:
            entities.append(maltego_entity_xml("maltego.IPv4Address", ip_val))
        # Organization/company (org often "ASxxxx Name")
        org = raw.get("org")
        if org:
            entities.append(maltego_entity_xml("maltego.Organization", org, {"org": org}))
        # timezone
        tz = raw.get("timezone")
        if tz:
            entities.append(maltego_entity_xml("maltego.String", tz, {"field": "timezone"}))

    # SHODAN -> services (ports/banners)
    shodan = service_map.get("shodan")
    if shodan and shodan.get("success"):
        raw = shodan.get("raw")
        # older Shodan host endpoint returns JSON with "data":[{port:..., product:..., transport:..., http: {...}}]
        data_list = None
        if isinstance(raw, dict):
            data_list = raw.get("data") or raw.get("ports") or []
        if isinstance(data_list, list) and data_list:
            for item in data_list:
                try:
                    port = item.get("port") or item
                    banner = None
                    if isinstance(item, dict):
                        # try common banner fields
                        banner = item.get("data") or item.get("banner") or item.get("http", {}).get("components") or item.get("product")
                    ent_val = f"{raw.get('ip_str') or ''}:{port}"
                    fields = {"port": port, "banner": banner or ""}
                    entities.append(maltego_entity_xml("maltego.Service", ent_val, fields))
                except Exception:
                    continue
        else:
            # fallback: attach entire raw as a string entity
            entities.append(maltego_entity_xml("maltego.Note", json.dumps(raw)[:1000]))

    # ABUSEIPDB -> abuse score & categories
    abuse = service_map.get("abuseipdb")
    if abuse and abuse.get("success") and isinstance(abuse.get("raw"), dict):
        raw = abuse["raw"]
        # AbuseIPDB v2 returns "data": { "abuseConfidenceScore": X, ... }
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        score = data.get("abuseConfidenceScore") or data.get("abuseConfidenceScore")
        categories = data.get("categories") or data.get("usageType") or ""
        ent_val = data.get("ipAddress") or ""
        if ent_val:
            fields = {"abuse_confidence_score": score or "", "categories": categories or "", "raw": json.dumps(data)[:1000]}
            entities.append(maltego_entity_xml("maltego.IPv4Address", ent_val, fields))
        else:
            entities.append(maltego_entity_xml("maltego.Note", f"AbuseIPDB score: {score} categories: {categories}"))

    # VIRUSTOTAL -> related domains / URLs / last_analysis_stats
    vt = service_map.get("virustotal")
    if vt and vt.get("success") and isinstance(vt.get("raw"), dict):
        raw = vt["raw"]
        # vt ip response: raw.get("data", {}).get("attributes", ...)
        if isinstance(raw.get("data"), dict):
            attrs = raw["data"].get("attributes", {})
            # related_domains
            rel_domains = attrs.get("resolutions") or attrs.get("last_https_certificate", {}).get("subject_alternative_name") or []
            if isinstance(rel_domains, list) and rel_domains:
                for d in rel_domains:
                    # when resolutions is list of dicts with "hostname"
                    if isinstance(d, dict) and d.get("hostname"):
                        entities.append(maltego_entity_xml("maltego.Domain", d.get("hostname")))
                    elif isinstance(d, str):
                        entities.append(maltego_entity_xml("maltego.Domain", d))
            # last_analysis_stats
            stats = attrs.get("last_analysis_stats") or {}
            if stats:
                entities.append(maltego_entity_xml("maltego.Note", f"VT stats: {json.dumps(stats)}"[:1000]))
        else:
            # fallback: try raw keys
            entities.append(maltego_entity_xml("maltego.Note", json.dumps(raw)[:1000]))

    # If no entities were produced, include a fallback note with summary
    if not entities:
        summary = {"services": [r["service"] + (":ok" if r.get("success") else ":err") for r in results_list]}
        entities.append(maltego_entity_xml("maltego.Note", json.dumps(summary)))

    # wrap in MaltegoMessage
    entities_joined = "\n".join(entities)
    xml = f"""<MaltegoMessage>
  <MaltegoTransformResponseMessage>
    <Entities>
{entities_joined}
    </Entities>
  </MaltegoTransformResponseMessage>
</MaltegoMessage>"""
    return xml

# --- Logging config ---
def setup_logging(log_path=None, verbose=False):
    # IMPORTANT: direct logs to stderr so stdout remains clean for Maltego XML
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_path:
        try:
            handlers.append(logging.FileHandler(log_path, encoding='utf-8'))
        except Exception:
            pass
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)

# --- main ---
def main():
    parser = argparse.ArgumentParser(description="Graph Enricher (Maltego-ready)")
    parser.add_argument("--entity", required=True, help="Entity value")
    parser.add_argument("--type", required=True, choices=["ip", "domain", "email", "phone", "facebook_account", "any"], help="Type of the entity")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--out", required=False, help="Write JSON output (path)")
    parser.add_argument("--log", required=False, help="Log file path")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging to stderr")
    parser.add_argument("--maltego", action="store_true", help="Output Maltego XML to stdout (for Maltego local transforms)")
    args = parser.parse_args()

    # load config (use utf-8-sig to tolerate BOM)
    with open(args.config, "r", encoding="utf-8-sig") as f:
        config = json.load(f)
    config = expand_in_obj(config)

    setup_logging(log_path=args.log, verbose=args.verbose)
    logging.info("Starting graph_enricher for entity=%s type=%s", args.entity, args.type)

    # run enrichment
    results = enrich_entity(args.entity, args.type, config)

    # optionally write JSON results to file if requested
    if args.out:
        payload = {"entity": args.entity, "type": args.type, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results}
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            logging.info("Wrote output JSON to %s", args.out)
        except Exception:
            logging.exception("Failed writing JSON output to %s", args.out)

    # If maltego mode -> build XML and print to stdout (no other stdout)
    if args.maltego:
        xml = build_maltego_response(results)
        # ensure stdout is clean (no logging)
        try:
            sys.stdout.write(xml)
        except Exception:
            logging.exception("Failed to write XML to stdout")
        return

    # Otherwise print a small JSON summary to stdout
    success_count = sum(1 for r in results if r.get("success"))
    summary = {"summary": {"entity": args.entity, "succeeded": success_count, "total": len(results)}}
    print(json.dumps(summary))

if __name__ == "__main__":
    main()
