"""
Pydantic Schemas for Playbooks & Simulation Engine
"""
from typing import Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class PlaybookStepItem(BaseModel):
    desc: str
    cmd: str
    estimated_seconds: Optional[int] = 5


class PlaybookCreate(BaseModel):
    name: str
    category: str = "General"
    description: str
    severity: str = "HIGH"
    steps: List[PlaybookStepItem]
    enabled: bool = True


class PlaybookResponse(BaseModel):
    id: int
    name: str
    category: str
    description: str
    severity: str
    steps: List[PlaybookStepItem]
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookExecutionRequest(BaseModel):
    execution_mode: str = "SIMULATION"  # Always verified as SIMULATION
    custom_steps: Optional[List[PlaybookStepItem]] = None


class PlaybookExecutionResponse(BaseModel):
    id: int
    incident_id: int
    playbook_id: Optional[int] = None
    requested_by: str
    approved_by: Optional[str] = None
    status: str
    execution_mode: str
    steps_results: List[Any]
    output_summary: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
