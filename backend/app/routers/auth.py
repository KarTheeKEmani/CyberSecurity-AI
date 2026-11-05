"""
Authentication Router
"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token, decode_token
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, RefreshTokenRequest, Token, UserResponse
from app.dependencies.auth import get_current_user, get_client_ip
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register a new user (default role ANALYST; ADMIN self-registration is strictly forbidden)."""
    email_clean = req.email.lower().strip()
    if not email_clean or "@" not in email_clean or "." not in email_clean:
        raise HTTPException(status_code=400, detail="Invalid email address format")

    if not req.password or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")

    # Enforce role restrictions: public registration cannot create ADMIN accounts
    requested_role = (req.role or "ANALYST").upper().strip()
    if requested_role == "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration with administrator privileges is not permitted. Contact a SOC administrator.",
        )

    assigned_role = requested_role if requested_role in ("ANALYST", "VIEWER") else "ANALYST"

    existing = db.query(User).filter(User.email == email_clean).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user = User(
        email=email_clean,
        full_name=req.full_name.strip() if req.full_name else email_clean.split("@")[0],
        password_hash=get_password_hash(req.password),
        role=assigned_role,
        is_active=True,
        mfa_enabled=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        action="USER_REGISTERED",
        resource="USER",
        resource_id=str(user.id),
        user=user,
        detail=f"User {user.email} registered with role {user.role}",
        ip_address=get_client_ip(request),
    )

    return user


from app.services.alert_correlation_service import evaluate_login_failure, evaluate_login_success


@router.post("/login", response_model=Token)
async def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate user credentials, generate signed JWT tokens, and record audit telemetry.
    Supports role selection demo mode if matching user profile exists.
    Correlates failed login bursts and suspicious logins following failed attempts.
    """
    email_clean = req.email.lower().strip()
    client_ip = get_client_ip(request)
    user = db.query(User).filter(User.email == email_clean).first()

    # If demo mode is active in non-production and user explicitly requested role, look up by requested role
    is_demo = settings.DEMO_MODE and not settings.is_production
    if not user and is_demo and req.role:
        # Fallback to role matching if demo user selected by role button
        target_role = req.role.upper()
        user = db.query(User).filter(User.role == target_role).first()

    if not user:
        log_audit_event(
            db=db,
            action="LOGIN_FAILED",
            resource="AUTH",
            resource_id=email_clean,
            user_email=email_clean,
            user_name="Unregistered User",
            detail=f"Failed login attempt for email {email_clean} — Account not found",
            severity="warning",
            ip_address=client_ip,
        )
        try:
            await evaluate_login_failure(db=db, email=email_clean, ip_address=client_ip)
        except Exception as e:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password or demo mode validation (strictly disabled in production)
    password_valid = verify_password(req.password, user.password_hash)
    if not password_valid and is_demo and req.password in ("demo1234", "Password123!"):
        password_valid = True

    if not password_valid:
        log_audit_event(
            db=db,
            action="LOGIN_FAILED",
            resource="AUTH",
            resource_id=user.email,
            user=user,
            detail=f"Failed login attempt for {user.email} — Invalid credentials",
            severity="warning",
            ip_address=client_ip,
        )
        try:
            await evaluate_login_failure(db=db, email=email_clean, ip_address=client_ip)
        except Exception as e:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact security admin.",
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    # Generate JWT tokens
    access_token = create_access_token(subject=user.email, role=user.role)
    refresh_token = create_refresh_token(subject=user.email, role=user.role)

    log_audit_event(
        db=db,
        action="LOGIN_SUCCESS",
        resource="AUTH",
        resource_id=user.email,
        user=user,
        detail=f"Successful JWT session authenticated for {user.email} [{user.role}]",
        severity="info",
        ip_address=client_ip,
    )

    # Correlate suspicious successful login after recent failed attempts
    try:
        await evaluate_login_success(db=db, email=user.email, ip_address=client_ip)
    except Exception as e:
        pass

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
    }


@router.post("/refresh")
def refresh_token(
    req: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """Exchange a valid refresh token for a new access token."""
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not active or not found",
        )

    new_access_token = create_access_token(subject=user.email, role=user.role)
    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }


@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Log out active session and record audit event."""
    log_audit_event(
        db=db,
        action="LOGOUT",
        resource="AUTH",
        resource_id=current_user.email,
        user=current_user,
        detail=f"User {current_user.email} signed out",
        ip_address=get_client_ip(request),
    )
    return {"status": "success", "message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user profile."""
    return current_user
