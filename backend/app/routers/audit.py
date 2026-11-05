"""
Audit Logs Router — Tamper-Evident Security Log Trail
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_
from app.core.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.analytics import AuditLogResponse, AuditLogListResponse
from app.dependencies.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit Trail"])


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve immutable audit logs with search and filter support."""
    query = db.query(AuditLog)

    if action:
        query = query.filter(func.lower(AuditLog.action) == action.lower())
    if resource:
        query = query.filter(func.lower(AuditLog.resource) == resource.lower())
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AuditLog.public_id.ilike(pattern),
                AuditLog.user_name.ilike(pattern),
                AuditLog.user_email.ilike(pattern),
                AuditLog.detail.ilike(pattern),
                AuditLog.resource_id.ilike(pattern),
            )
        )

    total = query.count()
    logs = (
        query.order_by(desc(AuditLog.timestamp))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "logs": logs,
    }
