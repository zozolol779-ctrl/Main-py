"""
OSINT Routes (DNS, Email, Username Enumeration)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.database import get_db
from core.security import require_role
from models.models import User
from services.osint.dns_enumerator import DNSEnumerator
from services.osint.email_osint import EmailOSINT
from services.osint.username_enumerator import UsernameEnumerator
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/osint", tags=["osint"])

dns_enum = DNSEnumerator()
email_osint = EmailOSINT()
username_enum = UsernameEnumerator()


# ==================== DNS Enumeration ====================

@router.get("/dns/a/{domain}")
async def dns_a_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get A records for domain"""
    
    result = dns_enum.get_a_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/aaaa/{domain}")
async def dns_aaaa_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get AAAA records (IPv6) for domain"""
    
    result = dns_enum.get_aaaa_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/mx/{domain}")
async def dns_mx_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get MX records for domain"""
    
    result = dns_enum.get_mx_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/ns/{domain}")
async def dns_ns_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get NS records for domain"""
    
    result = dns_enum.get_ns_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/txt/{domain}")
async def dns_txt_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get TXT records (SPF, DKIM, DMARC) for domain"""
    
    result = dns_enum.get_txt_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/cname/{domain}")
async def dns_cname_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get CNAME records for domain"""
    
    result = dns_enum.get_cname_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/soa/{domain}")
async def dns_soa_records(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get SOA records for domain"""
    
    result = dns_enum.get_soa_records(domain)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/reverse/{ip}")
async def dns_reverse_lookup(
    ip: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Perform reverse DNS lookup on IP"""
    
    result = dns_enum.reverse_dns(ip)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "dns", "data": result}


@router.get("/dns/enumerate/{domain}")
async def dns_full_enumeration(
    domain: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Perform comprehensive DNS enumeration"""
    
    result = dns_enum.full_enumeration(domain)
    
    return {"source": "dns", "data": result}


# ==================== Email OSINT ====================

@router.get("/email/validate")
async def email_validate(
    email: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Validate email format"""
    
    result = email_osint.validate_email(email)
    
    return {"source": "email", "data": result}


@router.post("/email/extract")
async def email_extract(
    text: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Extract emails from text"""
    
    emails = email_osint.extract_emails(text)
    
    return {
        "source": "email",
        "extracted_count": len(emails),
        "emails": emails
    }


@router.get("/email/hunter/domain/{domain}")
async def email_hunter_domain_search(
    domain: str,
    limit: int = 100,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Search for emails on domain using Hunter.io"""
    
    result = email_osint.hunter_domain_search(domain, limit=limit)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "hunter.io", "data": result}


@router.get("/email/hunter/verify/{email}")
async def email_hunter_verify(
    email: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Verify email using Hunter.io"""
    
    result = email_osint.hunter_email_verification(email)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "hunter.io", "data": result}


@router.get("/email/clearbit/{email}")
async def email_clearbit_lookup(
    email: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Lookup person info by email using Clearbit"""
    
    result = email_osint.clearbit_person_lookup(email)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "clearbit", "data": result}


# ==================== Username Enumeration ====================

@router.get("/username/check/{username}/{platform}")
async def username_check(
    username: str,
    platform: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Check if username exists on specific platform"""
    
    result = username_enum.check_username(username, platform)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {"source": "username_enumeration", "data": result}


@router.get("/username/enumerate/{username}")
async def username_enumerate(
    username: str,
    platforms: Optional[str] = None,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Enumerate username across multiple platforms"""
    
    platform_list = None
    if platforms:
        platform_list = platforms.split(",")
    
    result = username_enum.enumerate_username(username, platforms=platform_list)
    
    return {"source": "username_enumeration", "data": result}


@router.post("/username/reverse-email")
async def username_reverse_email(
    email: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Try to enumerate username from email"""
    
    result = username_enum.reverse_email_username(email)
    
    return {"source": "username_enumeration", "data": result}


@router.get("/username/email-variations/{username}")
async def username_email_variations(
    username: str,
    domains: Optional[str] = None,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Generate email format variations for username"""
    
    domain_list = None
    if domains:
        domain_list = domains.split(",")
    
    result = username_enum.check_email_variations(username, domains=domain_list)
    
    return {"source": "username_enumeration", "data": result}
