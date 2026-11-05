"""
AI Analysis Telemetry Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False, default="mock")  # mock, openai, gemini, anthropic
    model = Column(String(100), nullable=False, default="cyber-triage-v2")
    classification = Column(String(100), nullable=False)  # CONFIRMED_THREAT, CONFIRMED_BREACH, ATTACK_PREVENTED, POTENTIAL_THREAT, BENIGN
    severity_score = Column(Float, nullable=False, default=7.5)
    confidence = Column(Float, nullable=False, default=95.0)
    threat_type = Column(String(255), nullable=False, default="Generic Incident")
    attack_stage = Column(String(100), nullable=True)     # Initial Access, Execution, Persistence, etc.
    root_cause = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    recommendations = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    incident = relationship("Incident", back_populates="ai_analyses")
