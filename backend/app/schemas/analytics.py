"""
Pydantic Schemas for Audit Logs, API Keys, Integrations, Analytics, Notifications, and Real-Time Events
"""
from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, ConfigDict


# ---- Audit Schemas ----
class AuditLogResponse(BaseModel):
    id: int
    public_id: str
    user_id: Optional[int] = None
    user_email: str
    user_name: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    detail: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    severity: str
    ip_address: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    total: int
    logs: List[AuditLogResponse]


# ---- API Key Schemas ----
class ApiKeyCreate(BaseModel):
    name: str
    permissions: List[str] = ["incidents:read"]


class ApiKeyResponse(BaseModel):
    id: int
    public_id: str
    name: str
    created_by_name: str
    key_prefix: str
    permissions: List[str]
    status: str
    request_count: int
    created_at: datetime
    last_used_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ApiKeyCreatedResponse(ApiKeyResponse):
    raw_key: str  # Revealed ONLY once at creation


# ---- Integration Schemas ----
class IntegrationResponse(BaseModel):
    id: int
    name: str
    provider: str
    category: str
    status: str
    endpoint_url: Optional[str] = None
    configuration_metadata: Dict[str, Any] = {}
    last_checked_at: Optional[datetime] = None
    last_status_message: Optional[str] = None
    enabled: bool

    model_config = ConfigDict(from_attributes=True)


class IntegrationUpdate(BaseModel):
    enabled: Optional[bool] = None
    endpoint_url: Optional[str] = None
    configuration_metadata: Optional[Dict[str, Any]] = None


class IntegrationTestResponse(BaseModel):
    name: str
    provider: str
    status: str
    message: str
    timestamp: datetime


# ---- Analytics Schemas ----
class OverviewSummary(BaseModel):
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    investigating_incidents: int
    resolved_incidents: int
    avg_mttr_hours: float
    threats_prevented_pct: float
    systems_protected: int
    signals_analyzed: str


class TrendData(BaseModel):
    labels: List[str]
    critical: List[int]
    high: List[int]
    medium: List[int]
    low: List[int]


class AttackVectorItem(BaseModel):
    name: str
    count: int
    pct: float


class SeverityDist(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class HeatmapMatrix(BaseModel):
    systems: List[str]
    categories: List[str]
    scores: List[List[int]]


class AIMetricsData(BaseModel):
    triage_accuracy: float
    false_positive_rate: float
    avg_triage_time: float
    playbook_success_rate: float
    incidents_auto_contained: int
    total_triaged: int


class AnalyticsOverview(BaseModel):
    trends: TrendData
    attack_vectors: List[AttackVectorItem]
    severity_dist: SeverityDist
    heatmap: HeatmapMatrix
    ai_metrics: AIMetricsData
    mttr: List[float]


# ---- Notification Schemas ----
class NotificationResponse(BaseModel):
    id: int
    title: str
    message: Optional[str] = None
    color: str
    severity: str
    read: bool
    incident_id: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---- Real-Time Event Schemas ----
class WebSocketEvent(BaseModel):
    type: str  # incident.created, incident.updated, incident.status_changed, ai.analysis.completed, etc.
    timestamp: datetime
    data: Dict[str, Any]
