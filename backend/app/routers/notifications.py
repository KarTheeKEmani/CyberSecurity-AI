"""
Notifications Router
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.core.database import get_db
from app.models.notification import Notification
from app.models.user import User
from app.schemas.analytics import NotificationResponse
from app.dependencies.auth import get_current_user

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=List[NotificationResponse])
def list_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve list of recent security alerts and notifications."""
    return db.query(Notification).order_by(desc(Notification.created_at)).limit(30).all()


@router.post("/mark-all-read")
def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark all unread notifications as read."""
    db.query(Notification).filter(Notification.read == False).update({"read": True})
    db.commit()
    return {"status": "success", "message": "All notifications marked as read"}


@router.patch("/{id}/read")
def mark_single_read(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark specific notification as read."""
    notif = db.query(Notification).filter(Notification.id == id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.read = True
    db.commit()
    return {"status": "success", "id": id, "read": True}
