"""
Reconnaissance Routes (Shodan + GreyNoise)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.database import get_db
from core.security import require_role
from models.models import User
from services.enrichment.shodan import ShodanEnricher
from services.enrichment.greynoise import GreyNoiseEnricher
from services.enrichment.censys import CensysEnricher
from services.enrichment.urlhaus import URLhausChecker
from services.enrichment.phishtank import PhishTankChecker
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reconnaissance", tags=["reconnaissance"])

shodan = ShodanEnricher()
greynoise = GreyNoiseEnricher()
censys = CensysEnricher()
urlhaus = URLhausChecker()
phishtank = PhishTankChecker()


@router.get("/shodan/host/{ip}")
async def shodan_host_lookup(
    ip: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Lookup IP on Shodan for services and metadata"""
    
    result = shodan.host_lookup(ip)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "shodan",
        "ip": ip,
        "data": result
    }


@router.get("/shodan/search")
async def shodan_search(
    query: str,
    limit: int = 10,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Search Shodan for devices matching query"""
    
    if not query or len(query.strip()) < 2:
        raise HTTPException(status_code=400, detail="Query too short")
    
    result = shodan.search(query, limit=limit)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "shodan",
        "query": query,
        "data": result
    }


@router.get("/shodan/account")
async def shodan_account(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """Get Shodan account info and quota"""
    
    result = shodan.get_account_info()
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "shodan",
        "data": result
    }


@router.get("/greynoise/ip/{ip}")
async def greynoise_ip_lookup(
    ip: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Full IP lookup on GreyNoise for threat classification"""
    
    result = greynoise.ip_lookup(ip)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "greynoise",
        "ip": ip,
        "data": result
    }


@router.get("/greynoise/quick/{ip}")
async def greynoise_quick_check(
    ip: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Quick IP classification on GreyNoise (faster)"""
    
    result = greynoise.quick_check(ip)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "greynoise",
        "ip": ip,
        "data": result
    }


@router.post("/greynoise/bulk")
async def greynoise_bulk_check(
    ips: list,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Bulk check multiple IPs on GreyNoise (max 100)"""
    
    if not ips or len(ips) == 0:
        raise HTTPException(status_code=400, detail="No IPs provided")
    
    if len(ips) > 100:
        raise HTTPException(status_code=400, detail="Max 100 IPs per request")
    
    result = greynoise.bulk_check(ips)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "greynoise",
        "data": result
    }


@router.get("/greynoise/account")
async def greynoise_account(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """Get GreyNoise account info and quota"""
    
    result = greynoise.account_info()
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "greynoise",
        "data": result
    }


@router.get("/greynoise/actors")
async def greynoise_actors(
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get known threat actors from GreyNoise"""
    
    result = greynoise.actors()
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "greynoise",
        "data": result
    }


@router.post("/combined/{ip}")
async def combined_reconnaissance(
    ip: str,
    include_shodan: bool = True,
    include_greynoise: bool = True,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Combined reconnaissance on IP from multiple sources"""
    
    results = {}
    
    if include_shodan:
        results["shodan"] = shodan.host_lookup(ip)
    
    if include_greynoise:
        results["greynoise"] = greynoise.ip_lookup(ip)
    
    return {
        "ip": ip,
        "sources": results
    }


# ==================== CENSYS ENDPOINTS ====================

@router.post("/censys/search")
async def censys_search(
    query: str,
    limit: int = 50,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Search for hosts on Censys"""
    
    result = censys.search_hosts(query, limit=limit)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "censys",
        "query": query,
        "data": result
    }


@router.get("/censys/host/{ip}")
async def censys_host_details(
    ip: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get detailed host information from Censys"""
    
    result = censys.host_details(ip)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "censys",
        "ip": ip,
        "data": result
    }


@router.post("/censys/certificates")
async def censys_certificate_search(
    query: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Search for certificates on Censys"""
    
    result = censys.certificate_search(query)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "censys",
        "query": query,
        "data": result
    }


# ==================== URLHAUS ENDPOINTS ====================

@router.get("/urlhaus/url")
async def urlhaus_check_url(
    url: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Check if URL is malicious on URLhaus"""
    
    result = urlhaus.url_query(url)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "urlhaus",
        "data": result
    }


@router.get("/urlhaus/host/{host}")
async def urlhaus_check_host(
    host: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get all malicious URLs hosted on domain"""
    
    result = urlhaus.host_query(host)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "urlhaus",
        "host": host,
        "data": result
    }


@router.post("/urlhaus/payloads")
async def urlhaus_get_payloads(
    url: str,
    limit: int = 50,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Get payloads found at URL"""
    
    result = urlhaus.payloads_query(url, limit=limit)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "urlhaus",
        "url": url,
        "data": result
    }


# ==================== PHISHTANK ENDPOINTS ====================

@router.get("/phishtank/url")
async def phishtank_check_url(
    url: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Check if URL is reported as phishing"""
    
    result = phishtank.check_url(url)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "phishtank",
        "data": result
    }


@router.post("/phishtank/batch")
async def phishtank_batch_check(
    urls: list,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Batch check multiple URLs for phishing"""
    
    if not urls or len(urls) == 0:
        raise HTTPException(status_code=400, detail="URLs required")
    
    result = phishtank.batch_check(urls[:100])
    
    return {
        "source": "phishtank",
        "data": result
    }


@router.post("/phishtank/email")
async def phishtank_check_email_domain(
    email: str,
    current_user: User = Depends(require_role("analyst")),
    db: Session = Depends(get_db)
):
    """Check email domain for phishing infrastructure"""
    
    result = phishtank.extract_domain(email)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "source": "phishtank",
        "data": result
    }
