"""
AbuseIPDB Enrichment Service
"""
import requests
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class AbuseIPDBEnricher:
    """AbuseIPDB API integration for IP reputation"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
    
    def check_ip(self, ip: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """
        Check IP reputation against AbuseIPDB
        max_age_in_days: Max report age (1-365)
        """
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_in_days,
                "verbose": True
            }
            
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                return {
                    "found": True,
                    "ip": ip,
                    "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "usageType": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "hostnames": data.get("hostnames", []),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "is_vpn": data.get("isVpn", False),
                    "is_tor": data.get("isTor", False),
                    "is_proxy": data.get("isProxy", False),
                    "is_datacenter": data.get("isDatacenter", False)
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking IP with AbuseIPDB: {e}")
            return {"error": str(e)}
    
    def report_ip(self, ip: str, category: int, comment: str = "") -> Dict[str, Any]:
        """
        Report abusive IP
        category: 1-23 (see AbuseIPDB documentation)
        """
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            
            data = {
                "ip": ip,
                "category": category,
                "comment": comment
            }
            
            response = requests.post(
                f"{self.BASE_URL}/report",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 201:
                return {
                    "success": True,
                    "ip": ip,
                    "message": "IP reported successfully"
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error reporting IP to AbuseIPDB: {e}")
            return {"error": str(e)}
