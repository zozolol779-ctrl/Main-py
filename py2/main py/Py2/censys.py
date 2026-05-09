"""
Censys Reconnaissance Service
"""
import requests
import os
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

class CensysEnricher:
    """Censys API integration for internet asset discovery"""
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id or os.getenv("CENSYS_API_ID")
        self.api_secret = api_secret or os.getenv("CENSYS_API_SECRET")
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not configured")
    
    def _get_auth(self) -> tuple:
        """Get basic auth credentials"""
        return (self.api_id, self.api_secret)
    
    def search_hosts(self, query: str, limit: int = 50) -> Dict[str, Any]:
        """Search for hosts matching query"""
        if not self.api_id or not self.api_secret:
            return {"error": "Censys API credentials not configured"}
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/hosts/search",
                json={"q": query, "per_page": min(limit, 100)},
                auth=self._get_auth(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "found": True,
                    "query": query,
                    "total_results": data.get("total_hits", 0),
                    "results": [
                        {
                            "ip": result.get("ip"),
                            "services": result.get("services", []),
                            "location": result.get("location"),
                            "asn": result.get("asn"),
                            "os": result.get("os")
                        }
                        for result in data.get("result", [])[:limit]
                    ]
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error searching Censys: {e}")
            return {"error": str(e)}
    
    def host_details(self, ip: str) -> Dict[str, Any]:
        """Get detailed information about a host"""
        if not self.api_id or not self.api_secret:
            return {"error": "Censys API credentials not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/hosts/{ip}",
                auth=self._get_auth(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "ip": ip,
                    "services": data.get("services", []),
                    "location": data.get("location", {}),
                    "asn": data.get("autonomous_system", {}),
                    "operating_system": data.get("os", []),
                    "last_updated": data.get("last_updated"),
                    "certificates": data.get("tls", {}).get("certificates", []),
                    "dns": data.get("dns", {}),
                    "open_ports": [s.get("port") for s in data.get("services", [])]
                }
            
            if response.status_code == 404:
                return {"found": False, "ip": ip}
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error getting host details: {e}")
            return {"error": str(e)}
    
    def certificate_search(self, query: str) -> Dict[str, Any]:
        """Search for certificates"""
        if not self.api_id or not self.api_secret:
            return {"error": "Censys API credentials not configured"}
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/certificates/search",
                json={"q": query, "per_page": 50},
                auth=self._get_auth(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "query": query,
                    "total_results": data.get("total_hits", 0),
                    "results": [
                        {
                            "fingerprint": result.get("fingerprint_sha256"),
                            "subject": result.get("subject"),
                            "issuer": result.get("issuer"),
                            "validity_period_months": result.get("validity_period_months")
                        }
                        for result in data.get("result", [])
                    ]
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error searching certificates: {e}")
            return {"error": str(e)}
