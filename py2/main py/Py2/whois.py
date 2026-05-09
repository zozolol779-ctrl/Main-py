"""
WHOIS Enrichment Service
"""
import requests
import json
import os
from typing import Dict, Any, Optional
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class WhoisEnricher:
    """WHOIS information enrichment service"""
    
    # Free WHOIS APIs (alternatives to paid services)
    WHOIS_APIS = {
        "domain": "https://www.whoisxmlapi.com/api/v1",
        "ip": "https://ip-whois.whoisxmlapi.com/api/v1"
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or ".whois_cache"
        self.api_key = os.getenv("WHOIS_API_KEY", "")
        
        # Create cache directory
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _get_cache_path(self, key: str) -> str:
        """Get cache file path"""
        return os.path.join(self.cache_dir, f"{key}.json")
    
    def _load_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """Load data from cache"""
        cache_path = self._get_cache_path(key)
        
        if not os.path.exists(cache_path):
            return None
        
        try:
            # Check cache age (24 hours)
            file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_path))
            if file_age > timedelta(hours=24):
                return None
            
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            return None
    
    def _save_cache(self, key: str, data: Dict[str, Any]):
        """Save data to cache"""
        try:
            cache_path = self._get_cache_path(key)
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def get_domain_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        # Check cache first
        cached = self._load_cache(f"domain_{domain}")
        if cached:
            return cached
        
        # For demo: return structured response
        # In production, integrate with actual WHOIS API
        result = {
            "domain": domain,
            "cached": False,
            "note": "Full WHOIS integration requires API key"
        }
        
        # Try free API if available
        try:
            if self.api_key:
                params = {
                    "domain": domain,
                    "apiKey": self.api_key
                }
                response = requests.get(
                    f"{self.WHOIS_APIS['domain']}/whois",
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    result = {
                        "domain": domain,
                        "registrar": data.get("registrarName"),
                        "creation_date": data.get("createdDate"),
                        "update_date": data.get("updatedDate"),
                        "expiration_date": data.get("expiresDate"),
                        "registrant_name": data.get("registrant", {}).get("name"),
                        "registrant_email": data.get("registrant", {}).get("email"),
                        "registrant_country": data.get("registrant", {}).get("countryName"),
                        "name_servers": data.get("nameServers", [])
                    }
                    
                    self._save_cache(f"domain_{domain}", result)
        
        except Exception as e:
            logger.warning(f"Error fetching WHOIS for domain: {e}")
        
        return result
    
    def get_ip_whois(self, ip: str) -> Dict[str, Any]:
        """Get WHOIS information for IP address"""
        # Check cache first
        cached = self._load_cache(f"ip_{ip}")
        if cached:
            return cached
        
        result = {
            "ip": ip,
            "cached": False,
            "note": "Full WHOIS integration requires API key"
        }
        
        # Try free API if available
        try:
            if self.api_key:
                params = {
                    "ip": ip,
                    "apiKey": self.api_key
                }
                response = requests.get(
                    f"{self.WHOIS_APIS['ip']}/whois",
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    result = {
                        "ip": ip,
                        "organization": data.get("org", {}).get("name"),
                        "org_type": data.get("org", {}).get("type"),
                        "country": data.get("countryName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "asn": data.get("asn"),
                        "type": data.get("ipType")
                    }
                    
                    self._save_cache(f"ip_{ip}", result)
        
        except Exception as e:
            logger.warning(f"Error fetching WHOIS for IP: {e}")
        
        return result
