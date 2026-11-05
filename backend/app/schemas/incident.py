"""
Pydantic Schemas for Incidents & Threat Telemetry
"""
from typing import Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class RawLogEntry(BaseModel):
    time: str
    level: str
    msg: str
    detail: str


class IOCOut(BaseModel):
    id: int
    type: str
    value: str
    confidence: float
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MitreTechniqueOut(BaseModel):
    id: int
    technique_id: str
    technique_name: str
    tactic: str
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AIAnalysisOut(BaseModel):
    id: int
    provider: str
    model: str
    classification: str
    severity_score: float
    confidence: float
    threat_type: str
    attack_stage: Optional[str] = None
    root_cause: str
    summary: Optional[str] = None
    recommendations: List[Any] = []
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookStepOut(BaseModel):
    desc: str
    cmd: str


class PlaybookOut(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    steps: List[PlaybookStepOut] = []


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: Optional[str] = ""
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    category: Optional[str] = "General Threat"
    source: Optional[str] = "Manual Ingest"
    source_ip: Optional[str] = "Unknown"
    destination_ip: Optional[str] = None
    target_system: Optional[str] = "Unknown"
    assignee: Optional[str] = "Unassigned"
    tags: Optional[List[str]] = []
    raw_logs: Optional[List[dict]] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    target_system: Optional[str] = None
    assignee: Optional[str] = None
    tags: Optional[List[str]] = None


class IncidentStatusUpdate(BaseModel):
    status: str  # DETECTED, TRIAGED, INVESTIGATING, CONTAINMENT_PENDING, CONTAINED, ERADICATED, RESOLVED, CLOSED


class IncidentResponse(BaseModel):
    id: int
    public_id: str
    title: str
    description: str
    severity: str
    status: str
    category: str
    source: str
    source_ip: Optional[str] = "Unknown"
    destination_ip: Optional[str] = None
    target_system: Optional[str] = "Unknown"
    assignee: Optional[str] = "Unassigned"
    risk_score: float
    tags: List[str] = []
    raw_logs: List[dict] = []
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    iocs: List[IOCOut] = []
    mitre_techniques: List[MitreTechniqueOut] = []
    ai_analyses: List[AIAnalysisOut] = []

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    incidents: List[IncidentResponse]
