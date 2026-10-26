"""
Email Delivery Log & Notification History Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g. EML-2026-0847
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(255), nullable=False)
    body_text = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="QUEUED", index=True)  # QUEUED, ATTEMPTED, DELIVERED, SIMULATED, FAILED
    is_simulation = Column(Boolean, default=False, nullable=False)
    provider_response = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    rule = relationship("DetectionRule")
    incident = relationship("Incident")
