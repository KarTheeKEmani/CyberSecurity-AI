"""
Email Notifications Router — Notification rules, email history, test emails
"""
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.core.database import get_db
from app.core.config import settings
from app.models.email_log import EmailLog
from app.models.rule import DetectionRule
from app.models.user import User
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.services.audit_service import log_audit_event
from app.services.email_service import send_security_email, retry_email

router = APIRouter(prefix="/email", tags=["Email Notifications"])


# --- Schemas ---

class RuleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    rule_type: str
    description: str = ""
    severity: str = "HIGH"
    conditions: dict = {}
    actions: List[str] = ["SEND_EMAIL"]
    enabled: bool = True
    cooldown_minutes: int = Field(15, ge=1, le=1440)


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    cooldown_minutes: Optional[int] = Field(None, ge=1, le=1440)
    conditions: Optional[dict] = None
    actions: Optional[List[str]] = None


class TestEmailRequest(BaseModel):
    recipient: EmailStr


class EmailLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    public_id: str
    recipient: str
    subject: str
    status: str
    is_simulation: bool
    provider_response: Optional[str]
    retry_count: int
    sent_at: Optional[datetime]
    created_at: datetime


class RuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    rule_type: str
    description: str
    severity: str
    enabled: bool
    cooldown_minutes: int
    last_triggered_at: Optional[datetime]
    created_at: datetime


# --- Rules Endpoints ---

@router.get("/rules", response_model=List[RuleResponse])
def list_rules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all configured notification/detection rules."""
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()


@router.post("/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    req: RuleCreate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Create a new detection/notification rule (Admin only)."""
    valid_types = [
        "FAILED_LOGINS_BURST", "LOGIN_AFTER_FAILURES", "CRITICAL_INCIDENT_INGEST",
        "UNRESOLVED_INCIDENT", "BRUTE_FORCE", "HIGH_SEVERITY_ALERT", "CUSTOM"
    ]
    if req.rule_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid rule_type. Must be one of: {valid_types}")

    existing = db.query(DetectionRule).filter(DetectionRule.name == req.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"A detection rule with name '{req.name}' already exists.")

    rule = DetectionRule(
        name=req.name,
        rule_type=req.rule_type,
        description=req.description,
        severity=req.severity.upper(),
        conditions=req.conditions,
        actions=req.actions,
        enabled=req.enabled,
        cooldown_minutes=req.cooldown_minutes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    log_audit_event(
        db=db,
        action="DETECTION_RULE_CREATED",
        resource="DETECTION_RULE",
        resource_id=str(rule.id),
        user=current_user,
        detail=f"Detection rule '{rule.name}' created by {current_user.email}",
        severity="info",
        ip_address=get_client_ip(request),
    )
    return rule


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
def update_rule(
    rule_id: int,
    req: RuleUpdate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Update a detection rule (Admin only)."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if req.name is not None:
        rule.name = req.name
    if req.enabled is not None:
        rule.enabled = req.enabled
    if req.cooldown_minutes is not None:
        rule.cooldown_minutes = req.cooldown_minutes
    if req.conditions is not None:
        rule.conditions = req.conditions
    if req.actions is not None:
        rule.actions = req.actions
    rule.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(rule)

    log_audit_event(
        db=db,
        action="DETECTION_RULE_UPDATED",
        resource="DETECTION_RULE",
        resource_id=str(rule.id),
        user=current_user,
        detail=f"Detection rule '{rule.name}' updated by {current_user.email}",
        severity="info",
        ip_address=get_client_ip(request),
    )
    return rule


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Delete a detection rule (Admin only)."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule_name = rule.name
    db.delete(rule)
    db.commit()

    log_audit_event(
        db=db,
        action="DETECTION_RULE_DELETED",
        resource="DETECTION_RULE",
        resource_id=str(rule_id),
        user=current_user,
        detail=f"Detection rule '{rule_name}' deleted by {current_user.email}",
        severity="warning",
        ip_address=get_client_ip(request),
    )
    return {"status": "success", "message": f"Rule '{rule_name}' deleted"}


# --- Email Log Endpoints ---

@router.get("/logs", response_model=List[EmailLogResponse])
def list_email_logs(
    page: int = 1,
    page_size: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """View email delivery history (all authenticated users)."""
    return (
        db.query(EmailLog)
        .order_by(desc(EmailLog.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )


# --- Test Email Endpoint ---

@router.post("/test")
async def send_test_email(
    req: TestEmailRequest,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Send a test notification email to verify SMTP configuration (Admin only)."""
    log = await send_security_email(
        db=db,
        recipient=req.recipient,
        subject="CyberSentinel AI — Test Email Notification",
        event_title="Test Security Notification",
        severity="INFO",
        reason="Manual test triggered by administrator",
        evidence="This is a test email to verify your SMTP configuration is working correctly.",
        investigation_steps=[
            "Confirm this email was received successfully",
            "Verify the From address and formatting look correct",
            "Check the dashboard link below works",
        ],
        dashboard_url="http://localhost:8000",
    )

    log_audit_event(
        db=db,
        action="TEST_EMAIL_SENT",
        resource="EMAIL",
        resource_id=log.public_id,
        user=current_user,
        detail=f"Test email sent to {req.recipient} by {current_user.email} — Status: {log.status}",
        severity="info",
        ip_address=get_client_ip(request),
    )

    return {
        "status": log.status,
        "public_id": log.public_id,
        "recipient": log.recipient,
        "is_simulation": log.is_simulation,
        "provider_response": log.provider_response,
        "message": (
            "Email simulation recorded (demo mode active). "
            "Set EMAIL_ENABLED=true and EMAIL_DEMO_MODE=false to send real emails."
        ) if log.is_simulation else "Test email sent via SMTP provider.",
    }


# --- Config Status ---

@router.get("/config")
def get_email_config(current_user: User = Depends(require_role(["ADMIN"]))):
    """Return email configuration status (no secrets exposed)."""
    return {
        "email_enabled": settings.EMAIL_ENABLED,
        "demo_mode": settings.EMAIL_DEMO_MODE,
        "smtp_host": settings.SMTP_HOST if settings.EMAIL_ENABLED else "(not configured)",
        "smtp_port": settings.SMTP_PORT,
        "smtp_configured": bool(settings.SMTP_USERNAME),
        "from_address": settings.EMAIL_FROM_ADDRESS,
        "recipients_configured": len(settings.NOTIFICATION_RECIPIENTS),
        "recipients": settings.NOTIFICATION_RECIPIENTS,
        "mode_label": (
            "EMAIL SIMULATION" if settings.EMAIL_DEMO_MODE or not settings.EMAIL_ENABLED
            else "LIVE EMAIL"
        ),
    }


# --- Recipient Management ---

class RecipientsUpdateRequest(BaseModel):
    recipients: List[EmailStr] = Field(..., min_length=1, description="List of notification recipient email addresses")


@router.get("/recipients")
def get_notification_recipients(
    current_user: User = Depends(get_current_user),
):
    """Get the active email notification recipients."""
    return {
        "recipients": list(settings.NOTIFICATION_RECIPIENTS),
        "count": len(settings.NOTIFICATION_RECIPIENTS),
    }


@router.post("/recipients")
def update_notification_recipients(
    body: RecipientsUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Update active notification recipients list (Admin only)."""
    clean_recipients = [r.strip().lower() for r in body.recipients if r.strip()]
    if not clean_recipients:
        raise HTTPException(status_code=400, detail="At least one valid recipient email is required.")

    old_recipients = list(settings.NOTIFICATION_RECIPIENTS)
    settings.NOTIFICATION_RECIPIENTS = clean_recipients

    log_audit_event(
        db=db,
        action="NOTIFICATION_RECIPIENTS_UPDATED",
        resource="EMAIL_CONFIG",
        resource_id="recipients",
        user=current_user,
        detail=f"Notification recipients updated from {old_recipients} to {clean_recipients} by {current_user.email}",
        severity="info",
        ip_address=get_client_ip(request),
    )

    return {
        "status": "updated",
        "recipients": settings.NOTIFICATION_RECIPIENTS,
        "count": len(settings.NOTIFICATION_RECIPIENTS),
    }


# --- Email Retry ---

@router.post("/logs/{log_id}/retry", response_model=EmailLogResponse)
async def retry_email_delivery(
    log_id: int,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Retry sending a previously failed or queued email dispatch (Admin only)."""
    log = db.query(EmailLog).filter(EmailLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Email log entry not found")

    updated_log = await retry_email(db=db, log=log)

    log_audit_event(
        db=db,
        action="EMAIL_RETRIED",
        resource="EMAIL_LOG",
        resource_id=log.public_id,
        user=current_user,
        detail=f"Email dispatch {log.public_id} retried (attempt #{log.retry_count}) — Status: {log.status}",
        severity="info",
        ip_address=get_client_ip(request),
    )

    return updated_log
