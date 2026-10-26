"""
Incident Model representing Cyber Incidents and Threat Telemetry
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g. INC-2024-0847
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=False, default="")
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), nullable=False, default="DETECTED", index=True)  # DETECTED, TRIAGED, INVESTIGATING, CONTAINMENT_PENDING, CONTAINED, ERADICATED, RESOLVED, CLOSED
    category = Column(String(100), nullable=False, default="General Threat", index=True)
    source = Column(String(100), nullable=False, default="Manual")  # EDR, SIEM, WAF, Firewall, CloudTrail, DNS, etc.
    source_ip = Column(String(100), nullable=True, default="Unknown")
    destination_ip = Column(String(100), nullable=True)
    target_system = Column(String(255), nullable=True, default="Unknown")
    assignee = Column(String(255), nullable=True, default="Unassigned")
    risk_score = Column(Float, nullable=False, default=5.0)
    tags = Column(JSON, nullable=False, default=list)
    raw_logs = Column(JSON, nullable=False, default=list)

    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    iocs = relationship("IOC", back_populates="incident", cascade="all, delete-orphan")
    mitre_techniques = relationship("MitreTechnique", back_populates="incident", cascade="all, delete-orphan")
    ai_analyses = relationship("AIAnalysis", back_populates="incident", cascade="all, delete-orphan", order_by="desc(AIAnalysis.created_at)")
    playbook_executions = relationship("PlaybookExecution", back_populates="incident", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="incident", cascade="all, delete-orphan")
