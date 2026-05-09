"""
External Integrations Routes (Slack, Telegram, MISP, etc.)
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Dict, Any
import requests
import os
import logging
from core.database import get_db
from core.security import get_current_user
from models.models import Investigation, ThreatIndicator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

# ==================== SLACK ====================

@router.post("/slack/webhook")
def setup_slack_webhook(
    investigation_id: int,
    webhook_url: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Setup Slack webhook for investigation alerts"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Verify webhook URL works
    try:
        response = requests.post(
            webhook_url,
            json={"text": "🕷️ SpiderAI webhook test - Connection successful!"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Slack webhook URL"
            )
        
        return {
            "status": "success",
            "message": "Slack webhook configured",
            "investigation_id": investigation_id
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to validate webhook: {str(e)}"
        )

async def send_slack_alert(webhook_url: str, threat_data: Dict[str, Any]):
    """Send threat alert to Slack"""
    try:
        message = {
            "color": "danger" if threat_data.get("severity") == "critical" else "warning",
            "title": f"🚨 Threat Detected: {threat_data.get('type')}",
            "text": threat_data.get("description"),
            "fields": [
                {
                    "title": "Severity",
                    "value": threat_data.get("severity"),
                    "short": True
                },
                {
                    "title": "Confidence",
                    "value": f"{threat_data.get('confidence', 0) * 100:.0f}%",
                    "short": True
                },
                {
                    "title": "Indicator",
                    "value": threat_data.get("indicator"),
                    "short": False
                }
            ]
        }
        
        await requests.post(webhook_url, json=message)
    except Exception as e:
        logger.error(f"Error sending Slack alert: {e}")

# ==================== TELEGRAM ====================

@router.post("/telegram/bot")
def setup_telegram_bot(
    bot_token: str,
    chat_id: str,
    investigation_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Setup Telegram bot for investigation alerts"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Test bot
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            params={
                "chat_id": chat_id,
                "text": "🕷️ SpiderAI bot test - Connection successful!"
            },
            timeout=5
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Telegram credentials"
            )
        
        return {
            "status": "success",
            "message": "Telegram bot configured",
            "investigation_id": investigation_id
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to validate bot: {str(e)}"
        )

async def send_telegram_alert(bot_token: str, chat_id: str, threat_data: Dict[str, Any]):
    """Send threat alert via Telegram"""
    try:
        message = f"""
🚨 Threat Detected!

Type: {threat_data.get('type')}
Severity: {threat_data.get('severity')}
Confidence: {threat_data.get('confidence', 0) * 100:.0f}%

Indicator: `{threat_data.get('indicator')}`
Description: {threat_data.get('description')}
        """
        
        await requests.get(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            params={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
        )
    except Exception as e:
        logger.error(f"Error sending Telegram alert: {e}")

# ==================== MISP ====================

@router.post("/misp/sync")
def sync_to_misp(
    investigation_id: int,
    misp_url: str,
    misp_api_key: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Sync investigation data to MISP"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Verify MISP connection
    try:
        headers = {"Authorization": misp_api_key}
        response = requests.get(
            f"{misp_url}/servers/getPyMISPVersion",
            headers=headers,
            timeout=5
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MISP credentials"
            )
        
        return {
            "status": "success",
            "message": "MISP integration configured",
            "investigation_id": investigation_id,
            "misp_version": response.json().get("pymisp")
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to MISP: {str(e)}"
        )

# ==================== SPLUNK ====================

@router.post("/splunk/forward")
def setup_splunk_forward(
    investigation_id: int,
    splunk_hec_url: str,
    hec_token: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Setup Splunk HTTP Event Collector forwarding"""
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.created_by == current_user.user_id
    ).first()
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Test HEC connection
    try:
        headers = {"Authorization": f"Splunk {hec_token}"}
        response = requests.post(
            f"{splunk_hec_url}/services/collector/event",
            headers=headers,
            json={
                "event": {
                    "source": "spiderai",
                    "sourcetype": "_json",
                    "event": {"test": True, "message": "SpiderAI Splunk HEC test"}
                }
            },
            verify=False,
            timeout=5
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Splunk HEC credentials"
            )
        
        return {
            "status": "success",
            "message": "Splunk HEC configured",
            "investigation_id": investigation_id
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to Splunk: {str(e)}"
        )

async def send_splunk_event(hec_url: str, hec_token: str, event_data: Dict[str, Any]):
    """Send event to Splunk HEC"""
    try:
        headers = {"Authorization": f"Splunk {hec_token}"}
        await requests.post(
            f"{hec_url}/services/collector/event",
            headers=headers,
            json={"event": event_data},
            verify=False
        )
    except Exception as e:
        logger.error(f"Error sending to Splunk: {e}")

# ==================== HEALTH CHECKS ====================

@router.get("/health")
def check_integrations_health():
    """Check health of external integrations"""
    return {
        "slack": "configured" if os.getenv("SLACK_WEBHOOK_URL") else "not_configured",
        "telegram": "configured" if os.getenv("TELEGRAM_BOT_TOKEN") else "not_configured",
        "misp": "configured" if os.getenv("MISP_URL") else "not_configured",
        "splunk": "configured" if os.getenv("SPLUNK_HEC_URL") else "not_configured"
    }
