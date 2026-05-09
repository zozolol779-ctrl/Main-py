"""
OSINT Username and Social Media Enumeration Service
"""
import requests
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class UsernameEnumerator:
    """Username enumeration across platforms"""
    
    # Platforms to check
    PLATFORMS = {
        "twitter": "https://twitter.com/{username}",
        "github": "https://github.com/{username}",
        "linkedin": "https://linkedin.com/in/{username}",
        "reddit": "https://reddit.com/user/{username}",
        "instagram": "https://instagram.com/{username}",
        "facebook": "https://facebook.com/{username}",
        "youtube": "https://youtube.com/@{username}",
        "tiktok": "https://tiktok.com/@{username}",
        "pinterest": "https://pinterest.com/{username}",
        "telegram": "https://t.me/{username}",
        "mastodon": "https://mastodon.social/@{username}",
        "keybase": "https://keybase.io/{username}",
    }
    
    def check_username(self, username: str, platform: str) -> Dict[str, Any]:
        """Check if username exists on specific platform"""
        
        if platform not in self.PLATFORMS:
            return {"error": f"Unknown platform: {platform}"}
        
        url = self.PLATFORMS[platform].format(username=username)
        
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            
            # Different platforms return different status codes
            exists = response.status_code not in [404, 410, 403]
            
            return {
                "username": username,
                "platform": platform,
                "url": url,
                "status_code": response.status_code,
                "exists": exists
            }
        
        except Exception as e:
            logger.error(f"Error checking {platform}: {e}")
            return {
                "username": username,
                "platform": platform,
                "error": str(e)
            }
    
    def enumerate_username(self, username: str, platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enumerate username across multiple platforms"""
        
        if platforms is None:
            platforms = list(self.PLATFORMS.keys())
        
        results = {
            "username": username,
            "platforms_checked": len(platforms),
            "found_on": [],
            "not_found_on": [],
            "errors": []
        }
        
        for platform in platforms:
            if platform not in self.PLATFORMS:
                continue
            
            check_result = self.check_username(username, platform)
            
            if "error" in check_result:
                results["errors"].append({
                    "platform": platform,
                    "error": check_result["error"]
                })
            elif check_result.get("exists"):
                results["found_on"].append({
                    "platform": platform,
                    "url": check_result["url"]
                })
            else:
                results["not_found_on"].append(platform)
        
        return results
    
    def reverse_email_username(self, email: str) -> Dict[str, Any]:
        """Try to enumerate username from email"""
        
        # Common patterns: john.doe@example.com -> johndoe, john.doe, jdoe
        username = email.split("@")[0]  # johndoe (if no dot) or john.doe
        
        patterns = [
            username,  # john.doe
            username.replace(".", ""),  # johndoe
            username.split(".")[0] if "." in username else username,  # john
        ]
        
        results = {
            "email": email,
            "potential_usernames": patterns,
            "enumeration_results": {}
        }
        
        for pattern in patterns:
            results["enumeration_results"][pattern] = self.enumerate_username(pattern)
        
        return results
    
    def check_email_variations(self, username: str, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """Check common email format variations"""
        
        if domains is None:
            domains = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]
        
        email_formats = [
            f"{username}@{{domain}}",
            f"{username}@{{domain}}",
            f"{username.replace('.', '')}@{{domain}}",
            f"{username.replace('_', '.')}@{{domain}}",
        ]
        
        results = {
            "username": username,
            "domains": domains,
            "email_variations": []
        }
        
        for domain in domains:
            for fmt in email_formats:
                email = fmt.format(domain=domain)
                results["email_variations"].append(email)
        
        # Deduplicate
        results["email_variations"] = list(set(results["email_variations"]))
        
        return results
