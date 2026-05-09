"""
Shodan Enrichment Service
"""
import requests
import os
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

class ShodanEnricher:
    """Shodan API integration for device and service discovery"""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            logger.warning("Shodan API key not configured")
    
    def host_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Lookup IP address on Shodan
        Returns: Services, ports, hostnames, location, etc.
        """
        if not self.api_key:
            return {"error": "Shodan API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=10
            )
            
            if response.status_code == 404:
                return {"found": False, "ip": ip, "message": "IP not found in Shodan"}
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "found": True,
                    "ip": ip,
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("asn"),
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "services": [
                        {
                            "port": service.get("port"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "os": service.get("os")
                        }
                        for service in data.get("data", [])[:10]  # Limit to 10
                    ],
                    "http": data.get("http", {}),
                    "ssl": data.get("ssl", {}),
                    "uptime": data.get("uptime"),
                    "last_update": data.get("last_update")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error looking up IP on Shodan: {e}")
            return {"error": str(e)}
    
    def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """
        Search Shodan for devices matching query
        Example queries:
        - "Apache" - Devices running Apache
        - "city:Paris" - Devices in Paris
        - "org:Google" - Google devices
        """
        if not self.api_key:
            return {"error": "Shodan API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/shodan/host/search",
                params={
                    "query": query,
                    "key": self.api_key,
                    "limit": min(limit, 100)
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "found": True,
                    "query": query,
                    "total_results": data.get("total"),
                    "results": [
                        {
                            "ip": result.get("ip_str"),
                            "port": result.get("port"),
                            "hostnames": result.get("hostnames", []),
                            "organization": result.get("org"),
                            "isp": result.get("isp"),
                            "country": result.get("country_name")
                        }
                        for result in data.get("matches", [])[:limit]
                    ]
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error searching Shodan: {e}")
            return {"error": str(e)}
    
    def get_account_info(self) -> Dict[str, Any]:
        """Get Shodan account information and quota"""
        if not self.api_key:
            return {"error": "Shodan API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/account/profile",
                params={"key": self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "user": data.get("user"),
                    "credits": data.get("credits"),
                    "org": data.get("org"),
                    "plan": data.get("plan"),
                    "created": data.get("created")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error getting Shodan account info: {e}")
            return {"error": str(e)}
