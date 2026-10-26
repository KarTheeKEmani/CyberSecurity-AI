"""
Security Ecosystem Integration Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON
from app.core.database import Base


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    provider = Column(String(100), nullable=False)  # splunk, crowdstrike, paloalto, virustotal, aws, slack
    category = Column(String(100), nullable=False, default="SIEM") # SIEM, EDR, Firewall, Threat Intel, Cloud, Notification
    status = Column(String(50), nullable=False, default="SIMULATED") # SIMULATED, CONFIGURED, CONNECTED, DISABLED, ERROR
    endpoint_url = Column(String(500), nullable=True)
    configuration_metadata = Column(JSON, nullable=False, default=dict)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    last_status_message = Column(String(500), nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
