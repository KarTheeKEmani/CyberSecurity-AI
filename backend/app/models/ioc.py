"""
Indicator of Compromise (IOC) Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # IP, DOMAIN, URL, HASH, USERNAME, FILE
    value = Column(String(500), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=90.0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    incident = relationship("Incident", back_populates="iocs")
