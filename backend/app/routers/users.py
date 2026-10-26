"""
User Management Router (RBAC Administration)
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_password_hash
from app.models.user import User
from app.schemas.auth import UserResponse, UserCreate, UserUpdate
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/users", tags=["User Administration"])


@router.get("", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all registered platform users."""
    return db.query(User).order_by(User.id.asc()).all()


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    req: UserCreate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Admin-only user creation."""
    existing = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists with this email")

    user = User(
        email=req.email.lower().strip(),
        full_name=req.full_name,
        password_hash=get_password_hash(req.password),
        role=req.role.upper(),
        is_active=True,
        mfa_enabled=req.mfa_enabled,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        action="USER_CREATED",
        resource="USER",
        resource_id=str(user.id),
        user=current_user,
        detail=f"Admin {current_user.email} created user {user.email} with role {user.role}",
        new_value={"email": user.email, "role": user.role},
        severity="warning",
        ip_address=get_client_ip(request),
    )

    return user


@router.patch("/{id}", response_model=UserResponse)
def update_user(
    id: int,
    req: UserUpdate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Update user role or status (Admin only)."""
    user = db.query(User).filter(User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    old_status = user.is_active

    if req.full_name is not None:
        user.full_name = req.full_name
    if req.role is not None:
        user.role = req.role.upper()
    if req.is_active is not None:
        user.is_active = req.is_active
    if req.password is not None:
        user.password_hash = get_password_hash(req.password)
    if req.mfa_enabled is not None:
        user.mfa_enabled = req.mfa_enabled

    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        action="USER_MODIFIED",
        resource="USER",
        resource_id=str(user.id),
        user=current_user,
        detail=f"Admin {current_user.email} modified user {user.email} (Role: {old_role} → {user.role})",
        old_value={"role": old_role, "is_active": old_status},
        new_value={"role": user.role, "is_active": user.is_active},
        severity="warning",
        ip_address=get_client_ip(request),
    )

    return user
