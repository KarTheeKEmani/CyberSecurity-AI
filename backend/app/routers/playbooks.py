"""
Playbook System Router — Responsible Cybersecurity Simulation Engine
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.playbook import Playbook, PlaybookExecution
from app.models.incident import Incident
from app.models.user import User
from app.schemas.playbook import PlaybookResponse, PlaybookCreate, PlaybookExecutionRequest, PlaybookExecutionResponse
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.services.playbook_runner import run_playbook_simulation, recommend_playbooks_for_incident

router = APIRouter(tags=["Playbooks"])


@router.get("/playbooks", response_model=List[PlaybookResponse])
def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve catalog of all enabled automated response playbooks with structured metadata."""
    return db.query(Playbook).filter(Playbook.enabled == True).all()


@router.get("/playbooks/{id}", response_model=PlaybookResponse)
def get_playbook(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full playbook details including risk level, permissions, and preconditions."""
    pb = db.query(Playbook).filter(Playbook.id == id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.get("/incidents/{id}/playbook/recommend")
def get_playbook_recommendations(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Rank and return all applicable defensive playbooks for a specific incident.
    Scores each playbook against incident category, title, description, tags, and severity.
    Returns an ordered list with the primary (highest-score) recommendation flagged.
    """
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    ranked = recommend_playbooks_for_incident(db, incident)

    return {
        "incident_id": incident.id,
        "incident_public_id": incident.public_id,
        "incident_category": incident.category,
        "total_playbooks": len(ranked),
        "recommendations": [
            {
                "playbook_id": r["playbook"].id,
                "playbook_name": r["playbook"].name,
                "category": r["playbook"].category,
                "severity": r["playbook"].severity,
                "risk_level": getattr(r["playbook"], "risk_level", "HIGH"),
                "operational_impact": getattr(r["playbook"], "operational_impact", "Moderate"),
                "required_permissions": getattr(r["playbook"], "required_permissions", []) or [],
                "preconditions": getattr(r["playbook"], "preconditions", []) or [],
                "incident_types": getattr(r["playbook"], "incident_types", []) or [],
                "description": r["playbook"].description,
                "step_count": len(r["playbook"].steps or []),
                "score": r["score"],
                "match_reason": r["match_reason"],
                "is_primary": r["is_primary"],
            }
            for r in ranked
        ],
    }


@router.post("/incidents/{id}/playbook/execute", response_model=PlaybookExecutionResponse)
async def execute_playbook(
    id: int,
    req: PlaybookExecutionRequest = PlaybookExecutionRequest(),
    playbook_id: Optional[int] = None,
    request: Request = None,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Execute a defensive containment playbook in SIMULATION MODE with analyst oversight.
    Accepts playbook_id in request body or query param.
    Updates incident status to CONTAINED and records a complete audit trail.
    """
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    client_ip = get_client_ip(request) if request else "127.0.0.1"

    # Resolve playbook_id from body or query param
    resolved_playbook_id = req.playbook_id or playbook_id
    custom_steps_dict = [s.model_dump() for s in req.custom_steps] if req.custom_steps else None

    execution = await run_playbook_simulation(
        db=db,
        incident_id=incident.id,
        playbook_id=resolved_playbook_id,
        requested_by=current_user.full_name or current_user.email,
        approved_by=current_user.full_name or current_user.email,
        custom_steps=custom_steps_dict,
        client_ip=client_ip,
    )

    return execution
