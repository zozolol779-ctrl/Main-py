"""
GeoIP Enrichment Service
"""
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Conditional import for optional dependency
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP = True
    GeoIP2Error = geoip2.errors.GeoIP2Error
except ImportError:
    logger.warning("geoip2 library not found. GeoIP enrichment will be disabled.")
    HAS_GEOIP = False
    class GeoIP2Error(Exception): pass

class GeoIPEnricher:
    """MaxMind GeoIP2 integration for geolocation"""
    
    def __init__(self, db_path: Optional[str] = None):
        if not HAS_GEOIP:
            self.reader = None
            return

        self.db_path = db_path or os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
        self.reader = None
        self._init_reader()
    
    def _init_reader(self):
        """Initialize GeoIP2 database reader"""
        if not HAS_GEOIP:
            return

        if not os.path.exists(self.db_path):
            logger.warning(f"GeoIP database not found at {self.db_path}")
            return
        
        try:
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info("GeoIP database loaded successfully")
        except Exception as e:
            logger.error(f"Error loading GeoIP database: {e}")
    
    def get_location(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data for IP address"""
        if not self.reader:
            return {"error": "GeoIP database not available (Library missing or DB not found)"}
        
        try:
            response = self.reader.city(ip)
            
            return {
                "ip": ip,
                "country": {
                    "code": response.country.iso_code,
                    "name": response.country.name,
                    "is_eu": response.country.is_in_european_union
                },
                "city": {
                    "name": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "time_zone": response.location.time_zone,
                    "accuracy_radius": response.location.accuracy_radius
                },
                "postal": {
                    "code": response.postal.code
                },
                "subdivisions": [
                    {
                        "code": sub.iso_code,
                        "name": sub.name,
                        "confidence": sub.confidence
                    } for sub in response.subdivisions
                ],
                "traits": {
                    "is_satellite_provider": response.traits.is_satellite_provider,
                    "is_anycast": response.traits.is_anycast,
                    "is_anonymous_proxy": response.traits.is_anonymous_proxy,
                    "is_legitimate_proxy": response.traits.is_legitimate_proxy
                }
            }
        
        except GeoIP2Error as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            return {"error": str(e), "ip": ip}
        except Exception as e:
            logger.error(f"Error in GeoIP lookup: {e}")
            return {"error": str(e), "ip": ip}
    
    def get_asn(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for IP address"""
        if not HAS_GEOIP:
            return {"error": "GeoIP library not available"}

        # This requires GeoLite2-ASN.mmdb
        asn_db_path = self.db_path.replace("City", "ASN")
        
        if not os.path.exists(asn_db_path):
            return {"error": "ASN database not available"}
        
        try:
            reader = geoip2.database.Reader(asn_db_path)
            response = reader.asn(ip)
            
            result = {
                "ip": ip,
                "asn": response.autonomous_system_number,
                "organization": response.autonomous_system_organization
            }
            
            reader.close()
            return result
        
        except Exception as e:
            logger.error(f"Error in ASN lookup: {e}")
            return {"error": str(e), "ip": ip}
    
    def close(self):
        """Close database connection"""
        if self.reader:
            self.reader.close()
    
    def __del__(self):
        self.close()
