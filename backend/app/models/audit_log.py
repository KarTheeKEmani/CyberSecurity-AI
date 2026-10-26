"""
Tamper-Evident Security Audit Log Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g. AUD-8847
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False, default="System")
    action = Column(String(100), nullable=False, index=True)  # LOGIN_SUCCESS, INCIDENT_CREATED, TRIAGE_EXECUTED, etc.
    resource = Column(String(100), nullable=False, index=True) # INCIDENT, USER, API_KEY, PLAYBOOK, AUTH
    resource_id = Column(String(100), nullable=True)
    detail = Column(Text, nullable=False)
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    severity = Column(String(20), nullable=False, default="info")  # info, warning, critical
    ip_address = Column(String(50), nullable=True, default="127.0.0.1")
    user_agent = Column(String(255), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")
