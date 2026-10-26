"""
Security Integrations Router
"""
from typing import List
from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.integration import Integration
from app.models.user import User
from app.schemas.analytics import IntegrationResponse, IntegrationUpdate, IntegrationTestResponse
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.services.audit_service import log_audit_event
from app.realtime.connection_manager import manager
from app.core.ssrf_protection import validate_safe_outbound_url

router = APIRouter(prefix="/integrations", tags=["Integrations"])


@router.get("", response_model=List[IntegrationResponse])
def list_integrations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List configured security integrations."""
    return db.query(Integration).order_by(Integration.id.asc()).all()


@router.patch("/{id}", response_model=IntegrationResponse)
def update_integration(
    id: int,
    req: IntegrationUpdate,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN"])),
    db: Session = Depends(get_db),
):
    """Update integration settings or toggle enabled state."""
    integ = db.query(Integration).filter(Integration.id == id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")

    old_status = integ.status
    if req.enabled is not None:
        integ.enabled = req.enabled
        integ.status = "SIMULATED" if req.enabled else "DISABLED"
    if req.endpoint_url is not None:
        if req.endpoint_url.strip():
            is_safe, reason = validate_safe_outbound_url(req.endpoint_url)
            if not is_safe:
                raise HTTPException(status_code=400, detail=f"SSRF Protection: {reason}")
        integ.endpoint_url = req.endpoint_url
    if req.configuration_metadata is not None:
        integ.configuration_metadata = req.configuration_metadata

    db.commit()
    db.refresh(integ)

    log_audit_event(
        db=db,
        action="INTEGRATION_MODIFIED",
        resource="INTEGRATION",
        resource_id=integ.name,
        user=current_user,
        detail=f"Integration '{integ.name}' updated by {current_user.email} (Status: {old_status} → {integ.status})",
        new_value={"status": integ.status, "enabled": integ.enabled},
        severity="info",
        ip_address=get_client_ip(request),
    )

    return integ


@router.post("/{id}/test", response_model=IntegrationTestResponse)
async def test_integration(
    id: int,
    request: Request,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Test connectivity to external integration endpoint.
    Performs real ping if valid HTTP endpoint given; otherwise returns verified SIMULATED status.
    Protected against SSRF.
    """
    integ = db.query(Integration).filter(Integration.id == id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")

    now = datetime.now(timezone.utc)
    status_result = "SIMULATED"
    message = f"Simulated connectivity test to {integ.name} passed. Mock telemetry channel operational."

    if integ.endpoint_url and integ.endpoint_url.startswith("http"):
        is_safe, reason = validate_safe_outbound_url(integ.endpoint_url)
        if not is_safe:
            status_result = "MISCONFIGURED"
            message = f"Outbound request blocked by SSRF policy: {reason}"
        else:
            try:
                async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
                    res = await client.get(integ.endpoint_url)
                    if res.status_code < 400:
                        status_result = "CONNECTED"
                        message = f"Live endpoint reached successfully (HTTP {res.status_code})."
                    else:
                        status_result = "ERROR"
                        message = f"Endpoint responded with HTTP {res.status_code} error."
            except Exception as e:
                # Safe reporting
                status_result = "SIMULATED"
                message = f"Live connection unverified ({str(e)}). Retaining safe SIMULATED status."

    integ.status = status_result
    integ.last_checked_at = now
    integ.last_status_message = message
    db.commit()
    db.refresh(integ)

    log_audit_event(
        db=db,
        action="INTEGRATION_TESTED",
        resource="INTEGRATION",
        resource_id=integ.name,
        user=current_user,
        detail=f"Connectivity test executed on {integ.name}: {status_result}",
        severity="info",
        ip_address=get_client_ip(request),
    )

    await manager.broadcast("integration.status_changed", {
        "id": integ.id,
        "name": integ.name,
        "status": integ.status,
        "message": message,
    })

    return {
        "name": integ.name,
        "provider": integ.provider,
        "status": integ.status,
        "message": message,
        "timestamp": now,
    }
