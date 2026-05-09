"""
OSINT Email Validation and Discovery Service
"""
import re
import requests
import os
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class EmailOSINT:
    """Email validation and OSINT discovery"""
    
    EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    def __init__(self):
        self.hunter_api_key = os.getenv("HUNTER_IO_API_KEY")
        self.clearbit_api_key = os.getenv("CLEARBIT_API_KEY")
    
    def validate_email(self, email: str) -> Dict[str, Any]:
        """Basic email validation"""
        email = email.lower().strip()
        
        if not re.match(self.EMAIL_REGEX, email):
            return {
                "email": email,
                "valid": False,
                "reason": "Invalid email format"
            }
        
        return {
            "email": email,
            "valid": True,
            "format": "valid"
        }
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract all emails from text"""
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        return list(set(emails))  # Deduplicate
    
    def hunter_domain_search(self, domain: str, limit: int = 100) -> Dict[str, Any]:
        """Search for emails on domain using Hunter.io"""
        if not self.hunter_api_key:
            return {"error": "Hunter.io API key not configured"}
        
        try:
            response = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={
                    "domain": domain,
                    "limit": min(limit, 100),
                    "offset": 0
                },
                headers={"Authorization": f"Bearer {self.hunter_api_key}"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "domain": domain,
                    "emails": [
                        {
                            "email": result["value"],
                            "first_name": result.get("first_name"),
                            "last_name": result.get("last_name"),
                            "title": result.get("title"),
                            "department": result.get("department"),
                            "company": result.get("company"),
                            "type": result.get("type"),
                            "confidence": result.get("confidence")
                        }
                        for result in data.get("data", {}).get("emails", [])
                    ],
                    "total": data.get("data", {}).get("total")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error searching Hunter.io: {e}")
            return {"error": str(e)}
    
    def hunter_email_verification(self, email: str) -> Dict[str, Any]:
        """Verify email existence on Hunter.io"""
        if not self.hunter_api_key:
            return {"error": "Hunter.io API key not configured"}
        
        try:
            response = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={
                    "email": email
                },
                headers={"Authorization": f"Bearer {self.hunter_api_key}"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                email_data = data.get("data", {})
                
                return {
                    "email": email,
                    "result": email_data.get("result"),  # deliverable, undeliverable, unknown
                    "score": email_data.get("score"),
                    "smtp_server": email_data.get("smtp_server"),
                    "smtp_check": email_data.get("smtp_check"),
                    "accept_all": email_data.get("accept_all"),
                    "did_you_mean": email_data.get("did_you_mean")
                }
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error verifying email on Hunter.io: {e}")
            return {"error": str(e)}
    
    def clearbit_person_lookup(self, email: str) -> Dict[str, Any]:
        """Lookup person info by email using Clearbit"""
        if not self.clearbit_api_key:
            return {"error": "Clearbit API key not configured"}
        
        try:
            response = requests.get(
                "https://person.clearbit.com/v2/combined/find",
                params={"email": email},
                auth=(self.clearbit_api_key, ""),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                person = data.get("person", {})
                
                return {
                    "email": email,
                    "person": {
                        "name": person.get("name"),
                        "given_name": person.get("givenName"),
                        "family_name": person.get("familyName"),
                        "title": person.get("title"),
                        "role": person.get("role"),
                        "location": person.get("location"),
                        "time_zone": person.get("timeZone"),
                        "gender": person.get("gender"),
                        "bio": person.get("bio"),
                        "avatar": person.get("avatar")
                    },
                    "company": data.get("company", {}).get("name") if data.get("company") else None,
                    "domains": data.get("domains", [])
                }
            
            if response.status_code == 404:
                return {"email": email, "found": False}
            
            return {"error": f"API returned status {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Error looking up person on Clearbit: {e}")
            return {"error": str(e)}
