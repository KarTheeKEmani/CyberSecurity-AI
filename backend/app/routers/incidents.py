"""
Incidents Router — Comprehensive Incident Management with Lifecycle Validation
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, func
from app.core.database import get_db
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.mitre import MitreTechnique
from app.models.notification import Notification
from app.models.user import User
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentStatusUpdate,
    IncidentResponse,
    IncidentListResponse,
)
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.services.audit_service import log_audit_event
from app.realtime.connection_manager import manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])

VALID_TRANSITIONS = {
    "DETECTED": ["TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"],
    "TRIAGED": ["INVESTIGATING", "CONTAINMENT_PENDING", "CONTAINED", "RESOLVED", "CLOSED"],
    "INVESTIGATING": ["CONTAINMENT_PENDING", "CONTAINED", "ERADICATED", "RESOLVED", "CLOSED"],
    "CONTAINMENT_PENDING": ["CONTAINED", "INVESTIGATING", "RESOLVED"],
    "CONTAINED": ["ERADICATED", "INVESTIGATING", "RESOLVED"],
    "ERADICATED": ["RESOLVED", "INVESTIGATING", "CLOSED"],
    "RESOLVED": ["CLOSED", "INVESTIGATING"],
    "CLOSED": ["INVESTIGATING"],  # Reopen if new indicators emerge
}


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    category: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieve paginated list of security incidents with rich filtering and keyword search.
    """
    query = db.query(Incident)

    if severity:
        query = query.filter(func.lower(Incident.severity) == severity.lower())
    if status_filter:
        query = query.filter(func.lower(Incident.status) == status_filter.lower())
    if category:
        query = query.filter(func.lower(Incident.category) == category.lower())
    if assignee:
        query = query.filter(func.lower(Incident.assignee) == assignee.lower())
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Incident.public_id.ilike(search_pattern),
                Incident.title.ilike(search_pattern),
                Incident.description.ilike(search_pattern),
                Incident.source_ip.ilike(search_pattern),
                Incident.target_system.ilike(search_pattern),
                Incident.source.ilike(search_pattern),
            )
        )

    total = query.count()
    incidents = (
        query.order_by(desc(Incident.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "incidents": incidents,
    }


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    req: IncidentCreate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Ingest or create a new incident. Stores in PostgreSQL, commits, and broadcasts real-time events.
    """
    # Generate unique public ID
    now = datetime.now(timezone.utc)
    public_id = f"INC-2024-{uuid.uuid4().hex[:8].upper()}"
    severity_upper = req.severity.upper() if req.severity.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM"
    
    # Calculate initial risk score based on severity
    risk_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
    risk_score = risk_map.get(severity_upper, 5.0)

    incident = Incident(
        public_id=public_id,
        title=req.title,
        description=req.description or "",
        severity=severity_upper,
        status="DETECTED",
        category=req.category or "General Threat",
        source=req.source or "Manual Ingest",
        source_ip=req.source_ip or "Unknown",
        destination_ip=req.destination_ip,
        target_system=req.target_system or "Unknown",
        assignee=req.assignee or "Unassigned",
        risk_score=risk_score,
        tags=req.tags or [],
        raw_logs=req.raw_logs or [
            {"time": now.strftime("%H:%M:%S"), "level": "WARN", "msg": "Incident ingested", "detail": f"Source: {req.source} | Origin: {req.source_ip}"}
        ],
        detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    # Extract default IOC if source IP is provided
    if req.source_ip and req.source_ip not in ("Unknown", "None", ""):
        db.add(IOC(
            incident_id=incident.id,
            type="IP",
            value=req.source_ip,
            confidence=90.0,
            created_at=now,
        ))

    # Notification
    color_map = {"CRITICAL": "#FF3366", "HIGH": "#FF3366", "MEDIUM": "#FFAA00", "LOW": "#00D4FF"}
    notif = Notification(
        title=f"{severity_upper}: {incident.title[:45]}...",
        message=f"New telemetry alert on {incident.target_system} via {incident.source}",
        color=color_map.get(severity_upper, "#00D4FF"),
        severity=severity_upper.lower(),
        read=False,
        incident_id=incident.id,
        created_at=now,
    )
    db.add(notif)

    # Commit Transaction (Source of Truth)
    db.commit()
    db.refresh(incident)
    db.refresh(notif)

    # Audit Log
    log_audit_event(
        db=db,
        action="INCIDENT_CREATED",
        resource="INCIDENT",
        resource_id=incident.public_id,
        user=current_user,
        detail=f"Incident {incident.public_id} ({incident.severity}) created by {current_user.email}",
        new_value={"public_id": incident.public_id, "title": incident.title, "severity": incident.severity},
        severity="info" if incident.severity != "CRITICAL" else "critical",
        ip_address=get_client_ip(request),
    )

    # Broadcast Real-Time Events AFTER DB COMMIT
    await manager.broadcast("incident.created", {
        "id": incident.id,
        "public_id": incident.public_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "source": incident.source,
        "assignee": incident.assignee,
        "created_at": incident.created_at.isoformat(),
    })
    await manager.broadcast("notification.created", {
        "id": notif.id,
        "title": notif.title,
        "message": notif.message,
        "severity": notif.severity,
        "color": notif.color,
    })

    # Evaluate automated detection & notification rules (Phase 5)
    try:
        from app.services.alert_correlation_service import evaluate_incident_rules
        await evaluate_incident_rules(db=db, incident=incident)
    except Exception as e:
        pass

    return incident


@router.get("/{id}", response_model=IncidentResponse)
def get_incident(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve complete incident telemetry by ID."""
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{id}", response_model=IncidentResponse)
async def update_incident(
    id: int,
    req: IncidentUpdate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """Update incident properties."""
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_values = {}
    updated_fields = {}

    if req.title is not None:
        old_values["title"] = incident.title
        incident.title = req.title
        updated_fields["title"] = req.title
    if req.description is not None:
        incident.description = req.description
    if req.severity is not None:
        old_values["severity"] = incident.severity
        incident.severity = req.severity.upper()
        updated_fields["severity"] = incident.severity
    if req.category is not None:
        incident.category = req.category
    if req.source is not None:
        incident.source = req.source
    if req.source_ip is not None:
        incident.source_ip = req.source_ip
    if req.destination_ip is not None:
        incident.destination_ip = req.destination_ip
    if req.target_system is not None:
        incident.target_system = req.target_system
    if req.assignee is not None:
        old_values["assignee"] = incident.assignee
        incident.assignee = req.assignee
        updated_fields["assignee"] = req.assignee
    if req.tags is not None:
        incident.tags = req.tags

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(incident)

    log_audit_event(
        db=db,
        action="INCIDENT_MODIFIED",
        resource="INCIDENT",
        resource_id=incident.public_id,
        user=current_user,
        detail=f"Incident {incident.public_id} updated by {current_user.email}",
        old_value=old_values,
        new_value=updated_fields,
        ip_address=get_client_ip(request),
    )

    await manager.broadcast("incident.updated", {
        "id": incident.id,
        "public_id": incident.public_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "assignee": incident.assignee,
        "updated_at": incident.updated_at.isoformat(),
    })

    return incident


@router.patch("/{id}/status", response_model=IncidentResponse)
async def update_incident_status(
    id: int,
    req: IncidentStatusUpdate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Enforces valid incident lifecycle status transitions:
    DETECTED → TRIAGED → INVESTIGATING → CONTAINMENT_PENDING → CONTAINED → ERADICATED → RESOLVED → CLOSED
    """
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    current_status = incident.status.upper()
    new_status = req.status.upper()

    if current_status == new_status:
        return incident

    # Validate transition
    allowed = VALID_TRANSITIONS.get(current_status, [])
    if new_status not in allowed and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid lifecycle transition from {current_status} to {new_status}. Allowed next steps: {allowed}",
        )

    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.now(timezone.utc)

    if new_status == "RESOLVED":
        incident.resolved_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(incident)

    log_audit_event(
        db=db,
        action="INCIDENT_STATUS_CHANGED",
        resource="INCIDENT",
        resource_id=incident.public_id,
        user=current_user,
        detail=f"Status changed from {old_status} → {new_status}",
        old_value={"status": old_status},
        new_value={"status": new_status},
        severity="info",
        ip_address=get_client_ip(request),
    )

    await manager.broadcast("incident.status_changed", {
        "id": incident.id,
        "public_id": incident.public_id,
        "old_status": old_status,
        "new_status": new_status,
    })

    return incident


@router.delete("/{id}", status_code=status.HTTP_200_OK)
async def delete_incident(
    id: int,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete an incident (Admin authorization required)."""
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    public_id = incident.public_id
    db.delete(incident)
    db.commit()

    log_audit_event(
        db=db,
        action="INCIDENT_DELETED",
        resource="INCIDENT",
        resource_id=public_id,
        user=current_user,
        detail=f"Incident {public_id} permanently deleted by admin {current_user.email}",
        severity="warning",
        ip_address=get_client_ip(request),
    )

    await manager.broadcast("incident.deleted", {
        "id": id,
        "public_id": public_id,
    })

    return {"status": "success", "message": f"Incident {public_id} deleted"}
