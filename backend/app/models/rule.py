"""
Detection & Automation Rule Models
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    rule_type = Column(String(100), nullable=False, index=True)  # FAILED_LOGINS_BURST, LOGIN_AFTER_FAILURES, CRITICAL_INCIDENT_INGEST, UNRESOLVED_INCIDENT, BRUTE_FORCE
    description = Column(Text, nullable=False, default="")
    severity = Column(String(20), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    conditions = Column(JSON, nullable=False, default=dict)  # Thresholds, windows, filters
    actions = Column(JSON, nullable=False, default=list)  # ["CREATE_INCIDENT", "SEND_EMAIL", "BROADCAST_ALERT"]
    enabled = Column(Boolean, default=True, nullable=False)
    cooldown_minutes = Column(Integer, default=15, nullable=False)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    executions = relationship("AutomationExecution", back_populates="rule", cascade="all, delete-orphan")


class AutomationExecution(Base):
    __tablename__ = "automation_executions"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_name = Column(String(255), nullable=False)
    trigger_event = Column(String(255), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(50), nullable=False, default="TRIGGERED")  # TRIGGERED, SUPPRESSED_COOLDOWN, ACTIONS_COMPLETED, ACTION_FAILED
    outcome_details = Column(JSON, nullable=False, default=dict)
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    rule = relationship("DetectionRule", back_populates="executions")
    incident = relationship("Incident")
