"""
Playbook and Playbook Execution Models (Responsible Cybersecurity Simulation)
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    category = Column(String(100), nullable=False, default="General")
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="HIGH")
    risk_level = Column(String(20), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    operational_impact = Column(String(100), nullable=False, default="Moderate")  # Minimal, Low, Moderate, High, Severe
    required_permissions = Column(JSON, nullable=False, default=list)  # e.g. ["SOC Analyst", "Incident Responder"]
    preconditions = Column(JSON, nullable=False, default=list)  # prerequisites required before execution
    incident_types = Column(JSON, nullable=False, default=list)  # matching incident categories/tags
    steps = Column(JSON, nullable=False, default=list)  # list of {desc: str, cmd: str, estimated_seconds: int, ...}
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    executions = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True, index=True)
    requested_by = Column(String(255), nullable=False)
    approved_by = Column(String(255), nullable=True)
    status = Column(String(50), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    execution_mode = Column(String(50), nullable=False, default="SIMULATION")  # Always clearly identified as SIMULATION
    steps_results = Column(JSON, nullable=False, default=list)
    output_summary = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    incident = relationship("Incident", back_populates="playbook_executions")
    playbook = relationship("Playbook", back_populates="executions")
