"""
Audit Logging Service
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models.user import User
from app.realtime.connection_manager import manager


def log_audit_event(
    db: Session,
    action: str,
    resource: str,
    detail: str,
    user: Optional[User] = None,
    user_email: Optional[str] = None,
    user_name: Optional[str] = None,
    resource_id: Optional[str] = None,
    old_value: Optional[Any] = None,
    new_value: Optional[Any] = None,
    severity: str = "info",
    ip_address: str = "127.0.0.1",
    user_agent: Optional[str] = None,
) -> AuditLog:
    """
    Creates an immutable audit log entry in PostgreSQL and schedules a real-time event after commit.
    """
    public_id = f"AUD-{uuid.uuid4().hex[:10].upper()}"

    email = user_email or (user.email if user else "system@cybersentinel.ai")
    name = user_name or (user.full_name if user else "System Automated Engine")
    user_id = user.id if user else None

    # Never log sensitive data
    sanitized_old = old_value
    sanitized_new = new_value

    audit_entry = AuditLog(
        public_id=public_id,
        user_id=user_id,
        user_email=email,
        user_name=name,
        action=action,
        resource=resource,
        resource_id=str(resource_id) if resource_id else None,
        detail=detail,
        old_value=sanitized_old,
        new_value=sanitized_new,
        severity=severity,
        ip_address=ip_address,
        user_agent=user_agent,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)

    return audit_entry
