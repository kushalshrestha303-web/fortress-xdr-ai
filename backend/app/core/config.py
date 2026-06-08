"""Configuration settings for Fortress XDR AI"""

from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # API
    API_VERSION: str = "v1"
    API_TITLE: str = "Fortress XDR AI"
    API_DESCRIPTION: str = "AI-Powered Security Operations Center"
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost:5432/fortress_xdr"
    )
    
    # OpenSearch
    OPENSEARCH_URL: str = os.getenv(
        "OPENSEARCH_URL",
        "https://localhost:9200"
    )
    OPENSEARCH_USER: str = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "admin")
    OPENSEARCH_SSL_VERIFY: bool = False
    
    # Wazuh Integration
    WAZUH_API_URL: str = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER: str = os.getenv("WAZUH_API_USER", "admin")
    WAZUH_API_PASSWORD: str = os.getenv("WAZUH_API_PASSWORD", "admin")
    WAZUH_ALERT_INDEX: str = "wazuh-alerts-*"
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # AI/LLM
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4")
    OLLAMA_ENABLED: bool = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    
    # Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "change-me-in-production-super-secret-key-here"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_HOURS: int = 24
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
