"""
Configuration management for SpiderAI
"""
from pydantic_settings import BaseSettings
from typing import Optional, List
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Basic
    APP_NAME: str = "SpiderAI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://spider_user:spider_pass@localhost:5432/spider_ai"
    )
    
    # Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "your-super-secret-key-change-in-production-12345"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    
    # Enrichment APIs
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
    MAXMIND_LICENSE_KEY: Optional[str] = os.getenv("MAXMIND_LICENSE_KEY")
    WHOIS_API_KEY: Optional[str] = os.getenv("WHOIS_API_KEY")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # External Integrations
    SLACK_WEBHOOK_URL: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
    TELEGRAM_BOT_TOKEN: Optional[str] = os.getenv("TELEGRAM_BOT_TOKEN")
    MISP_URL: Optional[str] = os.getenv("MISP_URL")
    MISP_API_KEY: Optional[str] = os.getenv("MISP_API_KEY")
    SPLUNK_HEC_URL: Optional[str] = os.getenv("SPLUNK_HEC_URL")
    SPLUNK_HEC_TOKEN: Optional[str] = os.getenv("SPLUNK_HEC_TOKEN")
    
    # Sentry
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings instance
settings = Settings()

# Validate critical settings in production
if settings.ENVIRONMENT == "production":
    assert settings.SECRET_KEY != "your-super-secret-key-change-in-production-12345", \
        "SECRET_KEY must be changed in production!"
    assert settings.OPENAI_API_KEY, "OPENAI_API_KEY required in production"
    assert settings.DEBUG is False, "DEBUG must be False in production"

# Log configuration
import logging

logger = logging.getLogger(__name__)

if settings.ENVIRONMENT == "production":
    logger.warning(f"Running in PRODUCTION mode")
    logger.warning(f"Debug mode: {settings.DEBUG}")
else:
    logger.info(f"Running in {settings.ENVIRONMENT.upper()} mode")
    logger.info(f"Debug mode: {settings.DEBUG}")
