"""
AI Chatbot Service — Cybersecurity Investigation Assistant
Manages conversation persistence, incident context retrieval, and prompt injection protection.
"""
import logging
import uuid
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.chat import ChatConversation, ChatMessage
from app.models.incident import Incident
from app.models.ai_analysis import AIAnalysis
from app.models.ioc import IOC
from app.models.mitre import MitreTechnique
from app.models.user import User
from app.ai.provider import get_ai_provider
from app.core.config import settings

logger = logging.getLogger("chatbot_service")

# Prompt injection patterns to sanitize
INJECTION_PATTERNS = [
    r"ignore (previous|above|all) instructions?",
    r"(system|assistant):\s*",
    r"you are now",
    r"jailbreak",
    r"DAN mode",
    r"disregard (your|all) (training|instructions)",
    r"reveal (your|the) (system prompt|instructions)",
]


def _sanitize_input(text: str) -> str:
    """Strip prompt injection attempts from user input."""
    sanitized = text[:2000]  # Max 2000 chars per message
    for pattern in INJECTION_PATTERNS:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE)
    return sanitized.strip()


from app.models.playbook import Playbook, PlaybookExecution
from sqlalchemy import or_


def _build_incident_context(db: Session, incident_id: Optional[int], user: User) -> str:
    """Retrieve verified incident data from database to provide as grounded context."""
    if not incident_id:
        return ""

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return ""

    ctx_parts = [
        f"INCIDENT_RECORD: {incident.public_id}",
        f"Title: {incident.title}",
        f"Severity: {incident.severity} | Status: {incident.status} | Risk Score: {incident.risk_score}",
        f"Category: {incident.category} | Source: {incident.source}",
        f"Source IP: {incident.source_ip or 'N/A'} | Target System: {incident.target_system or 'N/A'} | Destination IP: {incident.destination_ip or 'N/A'}",
        f"Detected At: {incident.detected_at.isoformat() if incident.detected_at else 'unknown'}",
        f"Assignee: {incident.assignee or 'Unassigned'}",
        f"Description: {incident.description if incident.description else 'N/A'}",
    ]

    # Telemetry Raw Logs (observed facts)
    if incident.raw_logs and isinstance(incident.raw_logs, list):
        log_lines = []
        for l in incident.raw_logs[:6]:
            if isinstance(l, dict):
                log_lines.append(f"[{l.get('time', 'time')}] {l.get('level', 'INFO')}: {l.get('msg', '')} — {l.get('detail', '')}")
            else:
                log_lines.append(str(l))
        if log_lines:
            ctx_parts.append("Observed Telemetry Logs:\n" + "\n".join(log_lines))

    # IOCs (verified facts)
    iocs = db.query(IOC).filter(IOC.incident_id == incident.id).all()
    if iocs:
        ioc_list = ", ".join(f"{i.type}:{i.value}" for i in iocs[:10])
        ctx_parts.append(f"Confirmed IOCs: {ioc_list}")

    # MITRE techniques
    mitre = db.query(MitreTechnique).filter(MitreTechnique.incident_id == incident.id).all()
    if mitre:
        mitre_list = ", ".join(f"{m.technique_id} ({m.technique_name} - {m.tactic})" for m in mitre[:8])
        ctx_parts.append(f"MITRE Techniques: {mitre_list}")

    # Latest AI analysis
    ai_analysis = db.query(AIAnalysis).filter(
        AIAnalysis.incident_id == incident.id
    ).order_by(AIAnalysis.created_at.desc()).first()
    if ai_analysis:
        ctx_parts.append(
            f"AI Triage Findings: Classification={ai_analysis.classification}, "
            f"Confidence={ai_analysis.confidence}%, ThreatType={ai_analysis.threat_type}, "
            f"RootCause={ai_analysis.root_cause}"
        )

    # Compatible Playbooks
    pbs = db.query(Playbook).filter(
        Playbook.enabled == True,
        or_(
            Playbook.category.ilike(f"%{incident.category}%"),
            Playbook.severity == incident.severity,
        )
    ).limit(3).all()
    if not pbs:
        pbs = db.query(Playbook).filter(Playbook.enabled == True).limit(2).all()
    if pbs:
        pb_info = []
        for p in pbs:
            step_descs = "; ".join([s.get("desc", "") for s in (p.steps or [])[:4]])
            pb_info.append(f"Playbook '{p.name}' [Severity: {p.severity}, Category: {p.category}]: {p.description}. Steps: {step_descs}")
        ctx_parts.append("Available Defensive Playbooks:\n" + "\n".join(pb_info))

    # Associated Playbook Executions (if already run)
    executions = db.query(PlaybookExecution).filter(
        PlaybookExecution.incident_id == incident.id
    ).order_by(PlaybookExecution.started_at.desc()).limit(3).all()
    if executions:
        exec_info = []
        for e in executions:
            exec_info.append(f"Execution #{e.id} by {e.requested_by}: status={e.status}, mode={e.execution_mode}, summary={e.output_summary or 'Completed'}")
        ctx_parts.append("Playbook Execution History on Incident:\n" + "\n".join(exec_info))

    # Correlated / Related incidents
    filters = []
    if incident.source_ip and incident.source_ip not in ("Unknown", "None", ""):
        filters.append(Incident.source_ip == incident.source_ip)
    if incident.target_system and incident.target_system not in ("Unknown", "None", ""):
        filters.append(Incident.target_system == incident.target_system)
    if incident.category:
        filters.append(Incident.category == incident.category)

    if filters:
        related = db.query(Incident).filter(
            Incident.id != incident.id,
            or_(*filters)
        ).order_by(Incident.created_at.desc()).limit(4).all()
        if related:
            rel_info = [f"- {r.public_id}: {r.title} [{r.severity}/{r.status}] (target: {r.target_system}, IP: {r.source_ip})" for r in related]
            ctx_parts.append("Correlated Incidents:\n" + "\n".join(rel_info))

    return "\n".join(ctx_parts)


def _build_general_context(db: Session) -> str:
    """Build a brief summary of recent incidents for general context."""
    recent = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    if not recent:
        return "No incidents found in the database."

    lines = ["Recent incidents (last 5):"]
    for inc in recent:
        lines.append(f"- {inc.public_id}: {inc.title} [{inc.severity} / {inc.status}]")
    return "\n".join(lines)


async def chat_with_ai(
    db: Session,
    user: User,
    conversation_id: Optional[int],
    user_message: str,
    incident_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Process a chat message:
    1. Sanitize input for prompt injection
    2. Retrieve or create conversation
    3. Build verified DB context
    4. Call AI provider
    5. Persist both messages
    6. Return response
    """
    # Sanitize input
    safe_message = _sanitize_input(user_message)
    if not safe_message:
        return {
            "content": "Please enter a valid question.",
            "is_mock": True,
            "conversation_id": conversation_id,
        }

    # Get or create conversation
    if conversation_id:
        conversation = db.query(ChatConversation).filter(
            ChatConversation.id == conversation_id,
            ChatConversation.user_id == user.id,  # ownership check
        ).first()
        if not conversation:
            return {
                "content": "Conversation not found or access denied.",
                "is_mock": True,
                "conversation_id": None,
                "error": True,
            }
    else:
        conversation = ChatConversation(
            public_id=f"CHAT-{uuid.uuid4().hex[:10].upper()}",
            user_id=user.id,
            title=safe_message[:60] + ("..." if len(safe_message) > 60 else ""),
            incident_id=incident_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(conversation)
        db.flush()

    # Build context from database (verified facts only)
    if incident_id or conversation.incident_id:
        iid = incident_id or conversation.incident_id
        context = _build_incident_context(db, iid, user)
    else:
        context = _build_general_context(db)

    # Build message history (latest CHATBOT_MAX_HISTORY messages)
    history = db.query(ChatMessage).filter(
        ChatMessage.conversation_id == conversation.id,
    ).order_by(ChatMessage.created_at.asc()).limit(settings.CHATBOT_MAX_HISTORY).all()

    api_messages = [
        {"role": m.role, "content": m.content}
        for m in history
        if m.role in ("user", "assistant")
    ]
    api_messages.append({"role": "user", "content": safe_message})

    # Store user message
    user_msg = ChatMessage(
        conversation_id=conversation.id,
        role="user",
        content=safe_message,
        evidence_sources=[],
        is_mock=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user_msg)

    # Call AI
    provider = get_ai_provider()
    try:
        ai_response = await provider.chat(api_messages, context=context)
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        ai_response = {
            "content": (
                "⚠️ **AI Unavailable** — The AI provider encountered an error. "
                "Please check the provider configuration in Settings.\n\n"
                f"Error: {str(e)[:100]}"
            ),
            "is_mock": True,
            "provider": "error",
        }

    # Store assistant message
    assistant_msg = ChatMessage(
        conversation_id=conversation.id,
        role="assistant",
        content=ai_response["content"],
        evidence_sources=[],
        is_mock=ai_response.get("is_mock", True),
        created_at=datetime.now(timezone.utc),
    )
    db.add(assistant_msg)

    # Update conversation timestamp
    conversation.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(conversation)
    db.refresh(assistant_msg)

    return {
        "content": ai_response["content"],
        "is_mock": ai_response.get("is_mock", True),
        "provider": ai_response.get("provider", "mock"),
        "conversation_id": conversation.id,
        "conversation_public_id": conversation.public_id,
        "message_id": assistant_msg.id,
    }
