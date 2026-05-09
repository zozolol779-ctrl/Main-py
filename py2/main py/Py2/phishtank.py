"""
PhishTank Phishing Detection Service
"""
import requests
import os
from typing import Dict, Any, Optional, List
import logging
import hashlib

logger = logging.getLogger(__name__)

class PhishTankChecker:
    """PhishTank API integration for phishing detection"""
    
    BASE_URL = "https://checkurl.phishtank.com/checkurl/"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("PHISHTANK_API_KEY")
        if not self.api_key:
            logger.warning("PhishTank API key not configured")
    
    def check_url(self, url: str, format: str = "json") -> Dict[str, Any]:
        """Check if URL is reported as phishing"""
        try:
            response = requests.post(
                self.BASE_URL,
                data={
                    "url": url,
                    "format": format,
                    "app_token": self.api_key
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                results = data.get("results", {})
                
                return {
                    "url": url,
                    "is_phishing": results.get("in_database") == 1,
                    "phish_id": results.get("phish_id"),
                    "phish_detail_page": results.get("phish_detail_page"),
                    "verified": results.get("verified") == 1,
                    "verification_time": results.get("verification_time"),
                    "submission_time": results.get("submission_time"),
                    "status": results.get("online") if results.get("in_database") else None,
                    "target": results.get("target"),
                    "details": {
                        "in_database": results.get("in_database"),
                        "cache_age": data.get("cache_age"),
                        "cache_timestamp": data.get("cache_timestamp")
                    }
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error checking phishing URL: {e}")
            return {"error": str(e)}
    
    def batch_check(self, urls: List[str]) -> Dict[str, Any]:
        """Check multiple URLs"""
        results = []
        
        for url in urls[:100]:  # Limit to 100 per request
            result = self.check_url(url)
            results.append({
                "url": url,
                "is_phishing": result.get("is_phishing"),
                "phish_id": result.get("phish_id")
            })
        
        phishing_count = sum(1 for r in results if r.get("is_phishing"))
        
        return {
            "total_checked": len(results),
            "phishing_found": phishing_count,
            "clean_urls": len(results) - phishing_count,
            "results": results
        }
    
    def extract_domain(self, email: str) -> Dict[str, Any]:
        """Extract domain from email and check for phishing infrastructure"""
        try:
            domain = email.split("@")[1] if "@" in email else email
            
            # Check domain itself
            domain_check = self.check_url(f"http://{domain}")
            
            # Check common phishing patterns
            patterns = [
                f"http://www.{domain}",
                f"https://{domain}",
                f"https://www.{domain}",
            ]
            
            pattern_checks = []
            for pattern in patterns:
                check = self.check_url(pattern)
                if check.get("is_phishing"):
                    pattern_checks.append({
                        "url": pattern,
                        "is_phishing": True,
                        "phish_id": check.get("phish_id")
                    })
            
            return {
                "email": email,
                "domain": domain,
                "domain_phishing": domain_check.get("is_phishing"),
                "patterns_found": pattern_checks,
                "risk_level": "high" if domain_check.get("is_phishing") or pattern_checks else "low"
            }
        
        except Exception as e:
            logger.error(f"Error checking email domain: {e}")
            return {"error": str(e)}
