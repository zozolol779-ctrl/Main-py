"""
GreyNoise Enrichment Service
"""
import requests
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class GreyNoiseEnricher:
    """GreyNoise API integration for threat intelligence and IP classification"""
    
    BASE_URL = "https://api.greynoise.io/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GREYNOISE_API_KEY")
        if not self.api_key:
            logger.warning("GreyNoise API key not configured")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with API key"""
        return {
            "key": self.api_key,
            "User-Agent": "SpiderAI/1.0"
        }
    
    def ip_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Lookup IP address classification and threat data
        Returns classification, activity level, tags, etc.
        """
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ip/{ip}",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 404:
                return {"found": False, "ip": ip, "classification": "unknown"}
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "found": True,
                    "ip": ip,
                    "classification": data.get("classification"),  # benign, malicious, unknown
                    "seen": data.get("seen"),
                    "tags": data.get("tags", []),
                    "metadata": {
                        "country": data.get("metadata", {}).get("country"),
                        "country_code": data.get("metadata", {}).get("country_code"),
                        "city": data.get("metadata", {}).get("city"),
                        "organization": data.get("metadata", {}).get("organization"),
                        "asn": data.get("metadata", {}).get("asn"),
                        "reverse_dns": data.get("metadata", {}).get("reverse_dns")
                    },
                    "last_seen": data.get("last_seen"),
                    "first_seen": data.get("first_seen"),
                    "actor": data.get("actor"),
                    "intent": data.get("intent"),  # malicious, benign
                    "activity": data.get("activity"),
                    "confidence": data.get("confidence")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error looking up IP on GreyNoise: {e}")
            return {"error": str(e)}
    
    def quick_check(self, ip: str) -> Dict[str, Any]:
        """
        Quick classification check (faster, limited info)
        Returns only: classification, seen, last_seen
        """
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ip/quick/{ip}",
                headers=self._get_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "ip": ip,
                    "classification": data.get("classification"),
                    "seen": data.get("seen"),
                    "last_seen": data.get("last_seen")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error quick checking IP on GreyNoise: {e}")
            return {"error": str(e)}
    
    def bulk_check(self, ips: list) -> Dict[str, Any]:
        """
        Bulk check multiple IPs at once
        Limited by API quota and size
        """
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        if len(ips) > 100:
            ips = ips[:100]  # Limit to 100
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/ips",
                headers=self._get_headers(),
                json={"ips": ips},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "results": [
                        {
                            "ip": result.get("ip"),
                            "classification": result.get("classification"),
                            "seen": result.get("seen")
                        }
                        for result in data.get("ips", [])
                    ],
                    "remaining": data.get("remaining")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error bulk checking IPs on GreyNoise: {e}")
            return {"error": str(e)}
    
    def account_info(self) -> Dict[str, Any]:
        """Get account information and quota remaining"""
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/account",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "user": data.get("user"),
                    "quota": {
                        "lookup": data.get("lookup"),
                        "explore": data.get("explore"),
                        "total": data.get("total")
                    },
                    "organization": data.get("organization"),
                    "plan": data.get("plan")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error getting GreyNoise account info: {e}")
            return {"error": str(e)}
    
    def actors(self) -> Dict[str, Any]:
        """Get known threat actors from GreyNoise"""
        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/actors",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "actors": data.get("actors", []),
                    "count": len(data.get("actors", []))
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error getting GreyNoise actors: {e}")
            return {"error": str(e)}
