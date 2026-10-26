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
from app.services.playbook_runner import run_playbook_simulation

router = APIRouter(tags=["Playbooks"])


@router.get("/playbooks", response_model=List[PlaybookResponse])
def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve catalog of automated response playbooks."""
    return db.query(Playbook).filter(Playbook.enabled == True).all()


@router.get("/playbooks/{id}", response_model=PlaybookResponse)
def get_playbook(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve playbook details."""
    pb = db.query(Playbook).filter(Playbook.id == id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


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
    Updates incident status to CONTAINED and records complete audit trail.
    """
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    client_ip = get_client_ip(request) if request else "127.0.0.1"

    custom_steps_dict = [s.model_dump() for s in req.custom_steps] if req.custom_steps else None

    execution = await run_playbook_simulation(
        db=db,
        incident_id=incident.id,
        playbook_id=playbook_id,
        requested_by=current_user.full_name or current_user.email,
        approved_by=current_user.full_name or current_user.email,
        custom_steps=custom_steps_dict,
        client_ip=client_ip,
    )

    return execution
