"""
Application Configuration — Extended with Email, Mock Generator, and Chat settings
"""
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
import secrets


class Settings(BaseSettings):
    PROJECT_NAME: str = "AIAC Cyber — Incident Response Platform"
    VERSION: str = "3.0.0"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = "development"
    DEMO_MODE: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./aiac_cyber.db"

    # Security & JWT
    JWT_SECRET_KEY: str = "super-secret-jwt-key-for-aiac-cyber-soc-2026-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "null",  # Allows file:/// requests during local prototyping
    ]

    # AI Configuration
    AI_PROVIDER: str = "mock"   # 'mock', 'openai', 'gemini', 'anthropic'
    AI_API_KEY: str = ""
    AI_MODEL: str = "gpt-4o-mini"
    AI_TIMEOUT_SECONDS: int = 30
    CHATBOT_MAX_HISTORY: int = 20       # messages retained per conversation
    CHATBOT_RATE_LIMIT_PER_MINUTE: int = 20

    # Email / SMTP Configuration
    EMAIL_ENABLED: bool = False         # Set True to send real emails
    EMAIL_DEMO_MODE: bool = True        # If True, simulate but do not send
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""             # Never hardcode; use env var SMTP_PASSWORD
    SMTP_USE_TLS: bool = True
    EMAIL_FROM_ADDRESS: str = "security@cybersentinel.ai"
    EMAIL_FROM_NAME: str = "CyberSentinel AI"
    NOTIFICATION_RECIPIENTS: List[str] = ["2503A52483@sru.edu.in", "2503A52499@sru.edu.in"]

    # Mock Alert Generator
    MOCK_GENERATOR_ENABLED: bool = True
    MOCK_GENERATOR_INTERVAL_SECONDS: int = 50
    MOCK_GENERATOR_MAX_PER_HOUR: int = 72

    # Automated Alert Scheduler (independent of mock generator API)
    AUTO_ALERT_ENABLED: bool = True
    AUTO_ALERT_INTERVAL_SECONDS: int = 50

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.JWT_SECRET_KEY == "super-secret-jwt-key-for-aiac-cyber-soc-2026-change-in-production"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow",
    )


settings = Settings()
