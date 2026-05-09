"""
VirusTotal Enrichment Service
"""
import requests
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class VirusTotalEnricher:
    """VirusTotal API integration for malware and threat enrichment"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
    
    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against VirusTotal database
        Supports MD5, SHA1, SHA256
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                return {"found": False, "hash": file_hash}
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                return {
                    "found": True,
                    "hash": file_hash,
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                    "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                    "type_description": attributes.get("type_description"),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "names": attributes.get("names", []),
                    "size": attributes.get("size"),
                    "magic": attributes.get("magic")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking hash with VirusTotal: {e}")
            return {"error": str(e)}
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal database"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                url_id = data.get("data", {}).get("id")
                
                # Get URL analysis
                analysis_response = requests.get(
                    f"{self.BASE_URL}/urls/{url_id}",
                    headers=self.headers,
                    timeout=10
                )
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    attributes = analysis_data.get("data", {}).get("attributes", {})
                    
                    return {
                        "found": True,
                        "url": url,
                        "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                        "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                        "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                        "last_http_response_code": attributes.get("last_http_response_code"),
                        "title": attributes.get("title")
                    }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking URL with VirusTotal: {e}")
            return {"error": str(e)}
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain against VirusTotal database"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                return {
                    "found": True,
                    "domain": domain,
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                    "categories": attributes.get("categories", {}),
                    "creation_date": attributes.get("creation_date"),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "registrar": attributes.get("registrar")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking domain with VirusTotal: {e}")
            return {"error": str(e)}
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP address against VirusTotal database"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                return {
                    "found": True,
                    "ip": ip,
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                    "asn": attributes.get("asn"),
                    "country": attributes.get("country"),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "reputation": attributes.get("reputation")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking IP with VirusTotal: {e}")
            return {"error": str(e)}
