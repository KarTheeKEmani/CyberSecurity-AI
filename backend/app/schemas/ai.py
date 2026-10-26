"""
Pydantic Schemas for AI Engine and Triage
"""
from typing import Optional, List, Any, Union, Dict
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class TriageRequest(BaseModel):
    provider: Optional[str] = None  # mock, openai, gemini, anthropic
    model: Optional[str] = None
    force_reanalysis: bool = False


class AIPlaybookRecommendation(BaseModel):
    name: str
    steps: List[Dict[str, Any]] = []


class AIAnalysisResult(BaseModel):
    classification: str
    severity_score: float
    confidence: float
    threat_type: str
    attack_stage: Optional[str] = None
    root_cause: str
    summary: Optional[str] = None
    iocs: List[str] = []
    mitre_techniques: List[Any] = []
    recommendations: List[str] = []
    recommended_playbook: Optional[AIPlaybookRecommendation] = None
    provider: str
    model: str
    is_mock: bool = True
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AIModelConfig(BaseModel):
    provider: str
    model: str
    temperature: float = 0.1
    api_key_configured: bool = False
    is_mock: bool = True
