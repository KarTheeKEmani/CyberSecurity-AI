"""
Responsible Playbook Execution & Simulation Engine
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.playbook import Playbook, PlaybookExecution
from app.models.incident import Incident
from app.models.notification import Notification
from app.realtime.connection_manager import manager
from app.services.audit_service import log_audit_event


async def run_playbook_simulation(
    db: Session,
    incident_id: int,
    playbook_id: Optional[int],
    requested_by: str,
    approved_by: Optional[str] = None,
    custom_steps: Optional[List[Dict[str, Any]]] = None,
    client_ip: str = "127.0.0.1",
) -> PlaybookExecution:
    """
    Simulates defensive containment playbook execution step-by-step.
    Enforces SIMULATION MODE, logs every action, and updates incident status upon completion.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    steps_to_run = []
    playbook_name = "Custom Analyst Containment"
    if playbook_id:
        playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if playbook:
            playbook_name = playbook.name
            steps_to_run = playbook.steps or []
    elif custom_steps:
        steps_to_run = custom_steps

    if not steps_to_run:
        steps_to_run = [
            {"desc": "Isolate host network adapter (Simulated)", "cmd": "netsh advfirewall set allprofiles state on"},
            {"desc": "Terminate suspicious process hierarchy (Simulated)", "cmd": "taskkill /F /PID 4832 /T"},
            {"desc": "Block indicator at border firewall (Simulated)", "cmd": "iptables -I INPUT -s 185.220.101.45 -j DROP"},
        ]

    # Create Execution Record
    execution = PlaybookExecution(
        incident_id=incident.id,
        playbook_id=playbook_id,
        requested_by=requested_by,
        approved_by=approved_by or requested_by,
        status="RUNNING",
        execution_mode="SIMULATION",
        steps_results=[],
        output_summary=f"Executing {len(steps_to_run)} defensive steps in SIMULATION MODE for {incident.public_id}...",
        started_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    # Emit Playbook Started Event
    await manager.broadcast("playbook.started", {
        "execution_id": execution.id,
        "incident_id": incident.id,
        "incident_public_id": incident.public_id,
        "playbook_name": playbook_name,
        "execution_mode": "SIMULATION",
        "step_count": len(steps_to_run),
    })

    # Simulate execution of each step with safe delay
    step_results = []
    for idx, step in enumerate(steps_to_run, start=1):
        step_desc = step.get("desc", f"Defensive Step {idx}")
        step_cmd = step.get("cmd", "echo [SIMULATION]")
        
        # Synthetic simulation output
        step_result = {
            "step_index": idx,
            "description": step_desc,
            "command": step_cmd,
            "status": "SIMULATED_SUCCESS",
            "exit_code": 0,
            "output": f"[SIMULATION] Verification check passed: Action safely simulated against sandbox target.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        step_results.append(step_result)

    execution.steps_results = step_results
    execution.status = "COMPLETED"
    execution.output_summary = f"Successfully completed all {len(step_results)} simulated containment actions for {incident.public_id}."
    execution.completed_at = datetime.now(timezone.utc)

    # Transition Incident Status if appropriate
    old_status = incident.status
    if incident.status in ("DETECTED", "TRIAGED", "INVESTIGATING", "CONTAINMENT_PENDING"):
        incident.status = "CONTAINED"
        incident.updated_at = datetime.now(timezone.utc)

    # Create Notification
    notif = Notification(
        title=f"Playbook Simulated: {incident.public_id}",
        message=f"{playbook_name} completed in simulation mode. Incident transitioned to CONTAINED.",
        color="#00FF88",
        severity="success",
        read=False,
        incident_id=incident.id,
    )
    db.add(notif)
    db.commit()
    db.refresh(execution)

    # Audit Logging
    log_audit_event(
        db=db,
        action="PLAYBOOK_EXECUTED",
        resource="INCIDENT",
        resource_id=incident.public_id,
        user_email=requested_by,
        user_name=requested_by,
        detail=f"Simulated containment playbook '{playbook_name}' completed. Incident status changed: {old_status} → CONTAINED",
        old_value={"status": old_status},
        new_value={"status": "CONTAINED", "execution_mode": "SIMULATION"},
        severity="info",
        ip_address=client_ip,
    )

    # Broadcast completed events
    await manager.broadcast("playbook.completed", {
        "execution_id": execution.id,
        "incident_id": incident.id,
        "incident_public_id": incident.public_id,
        "status": "COMPLETED",
        "execution_mode": "SIMULATION",
        "new_incident_status": incident.status,
    })
    await manager.broadcast("incident.status_changed", {
        "id": incident.id,
        "public_id": incident.public_id,
        "old_status": old_status,
        "new_status": incident.status,
    })
    await manager.broadcast("notification.created", {
        "id": notif.id,
        "title": notif.title,
        "message": notif.message,
        "severity": notif.severity,
        "color": notif.color,
    })

    return execution
