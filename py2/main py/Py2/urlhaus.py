"""
URLhaus Malicious URL Detection Service
"""
import requests
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

class URLhausChecker:
    """URLhaus API integration for malicious URL detection"""
    
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    def url_query(self, url: str) -> Dict[str, Any]:
        """Check if URL is known malicious"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/url/",
                data={"url": url},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    return {
                        "url": url,
                        "found": data.get("results"),  # If empty, URL not found
                        "threat_type": data.get("threat", [None])[0] if data.get("threat") else None,
                        "host": data.get("host"),
                        "date_added": data.get("date_added"),
                        "larted": data.get("larted"),
                        "urlhaus_reference": data.get("urlhaus_reference")
                    }
                else:
                    return {"query_status": data.get("query_status")}
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking URL: {e}")
            return {"error": str(e)}
    
    def host_query(self, host: str) -> Dict[str, Any]:
        """Get all malicious URLs hosted on domain"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/host/",
                data={"host": host},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    return {
                        "host": host,
                        "found": bool(data.get("results")),
                        "urls": [
                            {
                                "url": result.get("url"),
                                "threat": result.get("threat"),
                                "date_added": result.get("date_added"),
                                "urlhaus_reference": result.get("urlhaus_reference")
                            }
                            for result in data.get("results", [])
                        ],
                        "total_urls": len(data.get("results", []))
                    }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error querying host: {e}")
            return {"error": str(e)}
    
    def payloads_query(self, url: str, limit: int = 50) -> Dict[str, Any]:
        """Get all payloads found at URL"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/payloads/",
                data={"url": url, "limit": min(limit, 1000)},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    return {
                        "url": url,
                        "found": bool(data.get("payloads")),
                        "payloads": [
                            {
                                "payload_type": payload.get("type"),
                                "payload": payload.get("payload"),
                                "sample": payload.get("sample"),
                                "firstseen": payload.get("firstseen"),
                                "lastseen": payload.get("lastseen")
                            }
                            for payload in data.get("payloads", [])
                        ],
                        "total_payloads": len(data.get("payloads", []))
                    }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error querying payloads: {e}")
            return {"error": str(e)}
    
    def signature_query(self, signature: str) -> Dict[str, Any]:
        """Search by malware signature"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/signature/",
                data={"signature": signature},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    return {
                        "signature": signature,
                        "urls": data.get("results", []),
                        "total_urls": len(data.get("results", []))
                    }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error querying signature: {e}")
            return {"error": str(e)}
