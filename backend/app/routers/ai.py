"""
AI Triage Router
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.models.incident import Incident
from app.models.ai_analysis import AIAnalysis
from app.models.ioc import IOC
from app.models.mitre import MitreTechnique
from app.models.user import User
from app.schemas.ai import TriageRequest, AIAnalysisResult, AIModelConfig
from app.dependencies.auth import get_current_user, require_role, get_client_ip
from app.ai.provider import get_ai_provider
from app.services.audit_service import log_audit_event
from app.realtime.connection_manager import manager

router = APIRouter(tags=["AI Triage Engine"])


@router.post("/incidents/{id}/triage", response_model=AIAnalysisResult)
async def triage_incident(
    id: int,
    req: TriageRequest = TriageRequest(),
    request: Request = None,
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"])),
    db: Session = Depends(get_db),
):
    """
    Triggers AI-Assisted Triage on the specified incident.
    Produces structured threat classification, root cause analysis, IOC extraction, MITRE mapping, and containment playbooks.
    """
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Broadcast AI Analysis Started Event
    await manager.broadcast("ai.analysis.started", {
        "incident_id": incident.id,
        "public_id": incident.public_id,
        "provider": settings.AI_PROVIDER,
        "message": f"AI Triage Engine analyzing telemetry for {incident.public_id}...",
    })

    provider = get_ai_provider()
    incident_dict = {
        "id": incident.id,
        "public_id": incident.public_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "category": incident.category,
        "source": incident.source,
        "source_ip": incident.source_ip,
        "target_system": incident.target_system,
        "raw_logs": incident.raw_logs,
    }

    try:
        result = await provider.triage_incident(incident_dict)
    except Exception as e:
        await manager.broadcast("ai.analysis.failed", {
            "incident_id": incident.id,
            "public_id": incident.public_id,
            "error": str(e),
        })
        raise HTTPException(status_code=500, detail=f"AI Triage failed: {str(e)}")

    # Store AI Analysis Record
    ai_record = AIAnalysis(
        incident_id=incident.id,
        provider=result.get("provider", "mock"),
        model=result.get("model", "aiac-cyber-v2.5"),
        classification=result.get("classification", "CONFIRMED_THREAT"),
        severity_score=result.get("severity_score", 8.0),
        confidence=result.get("confidence", 95.0),
        threat_type=result.get("threat_type", "Cyber Threat"),
        attack_stage=result.get("attack_stage", "Initial Access"),
        root_cause=result.get("root_cause", ""),
        summary=result.get("summary", ""),
        recommendations=result.get("recommendations", []),
        created_at=datetime.now(timezone.utc),
    )
    db.add(ai_record)

    # Ingest extracted IOCs if new
    existing_iocs = {i.value for i in db.query(IOC).filter(IOC.incident_id == incident.id).all()}
    for ioc_val in result.get("iocs", []):
        if ioc_val not in existing_iocs and len(ioc_val) > 2:
            ioc_type = "IP" if ("." in ioc_val and not "/" in ioc_val) else ("URL" if "http" in ioc_val else "HASH")
            db.add(IOC(
                incident_id=incident.id,
                type=ioc_type,
                value=ioc_val,
                confidence=result.get("confidence", 90.0),
                created_at=datetime.now(timezone.utc),
            ))
            existing_iocs.add(ioc_val)

    # Ingest MITRE techniques if new
    existing_mitre = {m.technique_id for m in db.query(MitreTechnique).filter(MitreTechnique.incident_id == incident.id).all()}
    for mt in result.get("mitre_techniques", []):
        t_id = mt.get("technique_id")
        if t_id and t_id not in existing_mitre:
            db.add(MitreTechnique(
                incident_id=incident.id,
                technique_id=t_id,
                technique_name=mt.get("technique_name", "Unknown"),
                tactic=mt.get("tactic", "Execution"),
            ))
            existing_mitre.add(t_id)

    # Update status to TRIAGED if it was in DETECTED
    if incident.status == "DETECTED":
        incident.status = "TRIAGED"
        incident.updated_at = datetime.now(timezone.utc)

    # Commit DB transaction
    db.commit()
    db.refresh(ai_record)
    db.refresh(incident)

    # Audit Logging
    client_ip = get_client_ip(request) if request else "127.0.0.1"
    log_audit_event(
        db=db,
        action="TRIAGE_EXECUTED",
        resource="INCIDENT",
        resource_id=incident.public_id,
        user=current_user,
        detail=f"AI Triage completed by {current_user.email} (Classification: {ai_record.classification}, Confidence: {ai_record.confidence}%)",
        severity="info",
        ip_address=client_ip,
    )

    # Broadcast AI Completed Event
    await manager.broadcast("ai.analysis.completed", {
        "incident_id": incident.id,
        "public_id": incident.public_id,
        "classification": ai_record.classification,
        "severity_score": ai_record.severity_score,
        "confidence": ai_record.confidence,
        "threat_type": ai_record.threat_type,
        "root_cause": ai_record.root_cause,
        "is_mock": ai_record.provider == "mock",
        "recommended_playbook": result.get("recommended_playbook"),
    })

    return result


@router.get("/ai/config", response_model=AIModelConfig)
def get_ai_configuration(current_user: User = Depends(get_current_user)):
    """Return active AI Provider configuration and simulation mode status."""
    return {
        "provider": settings.AI_PROVIDER,
        "model": settings.AI_MODEL,
        "temperature": 0.1,
        "api_key_configured": bool(settings.AI_API_KEY),
        "is_mock": settings.AI_PROVIDER == "mock" or not settings.AI_API_KEY,
    }
