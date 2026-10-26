"""
MITRE ATT&CK Technique Model
"""
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(50), nullable=False, index=True)  # e.g. T1059.001
    technique_name = Column(String(255), nullable=False)           # e.g. PowerShell
    tactic = Column(String(100), nullable=False)                   # e.g. Execution, Persistence
    description = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="mitre_techniques")
