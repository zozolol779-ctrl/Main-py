import os
import requests
import shodan
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

class LocalEnrichment:
    def __init__(self):
        self.whois_key = os.getenv("WHOISXML_KEY")
        self.shodan_key = os.getenv("SHODAN_KEY")

        if self.shodan_key:
            self.shodan_api = shodan.Shodan(self.shodan_key)
        else:
            self.shodan_api = None

    def is_private_ip(self, ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
        )

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        result = {}

        # ✅ IP داخلي
        if self.is_private_ip(ip):
            return {
                "country": "Internal",
                "asn": "Private Network",
                "source": "Local",
            }

        # ✅ WHOISXML (ملكية + ASN)
        if self.whois_key:
            try:
                url = f"https://api.whoisxmlapi.com/v1?apiKey={self.whois_key}&ipAddress={ip}"
                r = requests.get(url, timeout=20)
                if r.status_code == 200:
                    result["whois"] = r.json()
            except Exception as e:
                result["whois_error"] = str(e)

        # ✅ SHODAN (بورتات + نظام + منظمة)
        if self.shodan_api:
            try:
                data = self.shodan_api.host(ip)
                result["shodan"] = {
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "country": data.get("country_name"),
                    "isp": data.get("isp"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames"),
                }
            except Exception as e:
                result["shodan_error"] = str(e)

        return result

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        if not self.whois_key:
            return {"error": "WHOISXML_KEY not set"}

        try:
            url = f"https://api.whoisxmlapi.com/v1?apiKey={self.whois_key}&domainName={domain}"
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            return {"error": str(e)}

        return {}
