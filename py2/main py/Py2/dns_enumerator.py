"""
OSINT DNS Enumeration Service
"""
import dns.resolver
import dns.zone
import dns.rdatatype
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class DNSEnumerator:
    """DNS enumeration for reconnaissance"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.timeout = 5
    
    def get_a_records(self, domain: str) -> Dict[str, Any]:
        """Get A records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            
            return {
                "type": "A",
                "domain": domain,
                "records": [str(rdata) for rdata in answers]
            }
        except Exception as e:
            logger.error(f"Error getting A records: {e}")
            return {"error": str(e)}
    
    def get_aaaa_records(self, domain: str) -> Dict[str, Any]:
        """Get AAAA records (IPv6) for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            
            return {
                "type": "AAAA",
                "domain": domain,
                "records": [str(rdata) for rdata in answers]
            }
        except Exception as e:
            logger.error(f"Error getting AAAA records: {e}")
            return {"error": str(e)}
    
    def get_mx_records(self, domain: str) -> Dict[str, Any]:
        """Get MX records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            
            return {
                "type": "MX",
                "domain": domain,
                "records": [
                    {
                        "priority": int(rdata.preference),
                        "exchange": str(rdata.exchange)
                    }
                    for rdata in answers
                ]
            }
        except Exception as e:
            logger.error(f"Error getting MX records: {e}")
            return {"error": str(e)}
    
    def get_ns_records(self, domain: str) -> Dict[str, Any]:
        """Get NS records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            
            return {
                "type": "NS",
                "domain": domain,
                "records": [str(rdata) for rdata in answers]
            }
        except Exception as e:
            logger.error(f"Error getting NS records: {e}")
            return {"error": str(e)}
    
    def get_txt_records(self, domain: str) -> Dict[str, Any]:
        """Get TXT records for domain (SPF, DKIM, DMARC)"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            
            return {
                "type": "TXT",
                "domain": domain,
                "records": [str(rdata) for rdata in answers]
            }
        except Exception as e:
            logger.error(f"Error getting TXT records: {e}")
            return {"error": str(e)}
    
    def get_cname_records(self, domain: str) -> Dict[str, Any]:
        """Get CNAME records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            
            return {
                "type": "CNAME",
                "domain": domain,
                "records": [str(rdata) for rdata in answers]
            }
        except Exception as e:
            logger.error(f"Error getting CNAME records: {e}")
            return {"error": str(e)}
    
    def get_soa_records(self, domain: str) -> Dict[str, Any]:
        """Get SOA records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            
            records = []
            for rdata in answers:
                records.append({
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum
                })
            
            return {
                "type": "SOA",
                "domain": domain,
                "records": records
            }
        except Exception as e:
            logger.error(f"Error getting SOA records: {e}")
            return {"error": str(e)}
    
    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup on IP"""
        try:
            # Reverse the IP to create PTR query
            addr = dns.ipv4.to_digestable(ip)
            ptrs = dns.resolver.resolve(dns.reversename.from_ipv4(ip), "PTR")
            
            return {
                "ip": ip,
                "reverse_dns": [str(ptr) for ptr in ptrs]
            }
        except Exception as e:
            logger.error(f"Error reverse DNS lookup: {e}")
            return {"error": str(e)}
    
    def full_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration"""
        results = {
            "domain": domain,
            "records": {}
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results["records"][record_type] = [str(rdata) for rdata in answers]
            except:
                results["records"][record_type] = []
        
        return results
