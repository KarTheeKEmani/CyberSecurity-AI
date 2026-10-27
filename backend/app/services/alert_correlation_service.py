"""
Alert Correlation & Automated Rule Engine Service.
Monitors security telemetry, correlates authentication anomaly patterns
(e.g., brute-force bursts, suspicious logins after repeated failures),
evaluates incoming incidents against configurable DetectionRules,
and coordinates automated incident generation and email dispatches.
"""
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.config import settings
from app.models.incident import Incident
from app.models.notification import Notification
from app.models.audit_log import AuditLog
from app.models.rule import DetectionRule, AutomationExecution
from app.models.ioc import IOC
from app.realtime.connection_manager import manager
from app.services.email_service import send_security_email

logger = logging.getLogger("alert_correlation")


def is_rule_in_cooldown(rule: DetectionRule, account: Optional[str] = None, db: Optional[Session] = None) -> bool:
    """Check if a detection rule is currently within its cooldown window (optionally scoped to a specific account)."""
    cooldown_delta = timedelta(minutes=rule.cooldown_minutes or 15)
    now = datetime.now(timezone.utc)

    if account and db:
        cutoff = now - cooldown_delta
        recent_execs = (
            db.query(AutomationExecution)
            .filter(
                AutomationExecution.rule_id == rule.id,
                AutomationExecution.executed_at >= cutoff,
            )
            .all()
        )
        for ex in recent_execs:
            details = ex.outcome_details or {}
            if details.get("account") == account or details.get("target_email") == account:
                return True
        return False

    if not rule.last_triggered_at:
        return False
    last = rule.last_triggered_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) < cooldown_delta


async def evaluate_login_failure(
    db: Session,
    email: str,
    ip_address: str,
) -> Optional[Incident]:
    """
    Evaluates failed login telemetry for brute-force patterns.
    Triggered whenever a login attempt fails in auth router.
    """
    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.rule_type == "FAILED_LOGINS_BURST", DetectionRule.enabled == True)
        .order_by(DetectionRule.id.asc())
        .all()
    )
    if not rules:
        return None

    is_loopback = ip_address.lower() in ("127.0.0.1", "localhost", "testclient", "unknown", "")

    for rule in rules:
        if is_rule_in_cooldown(rule, account=email, db=db):
            logger.debug(f"[CORRELATION] Rule '{rule.name}' is in cooldown for account '{email}'; skipping.")
            continue

        conditions = rule.conditions or {}
        threshold = int(conditions.get("threshold", 5))
        window_minutes = int(conditions.get("window_minutes", 10))

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        failures_query = db.query(AuditLog).filter(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.timestamp >= cutoff,
        )

        if is_loopback:
            matching_failures = failures_query.filter(AuditLog.user_email == email).count()
        else:
            matching_failures = failures_query.filter(
                (AuditLog.user_email == email) | (AuditLog.ip_address == ip_address)
            ).count()

        if matching_failures < threshold:
            continue

        logger.warning(
            f"[CORRELATION] Brute-force threshold met: {matching_failures} failures "
            f"for email={email}, ip={ip_address} in {window_minutes}m (threshold={threshold})"
        )
        break
    else:
        return None

    now = datetime.now(timezone.utc)
    public_id = f"INC-2024-{uuid.uuid4().hex[:8].upper()}"

    # 1. Create Incident
    incident = Incident(
        public_id=public_id,
        title=f"Brute-Force Attack Detected: {matching_failures} Failed Logins ({email})",
        description=(
            f"Automated correlation detected {matching_failures} failed authentication attempts "
            f"targeting account '{email}' from IP {ip_address} within a {window_minutes}-minute window. "
            f"Potential automated credential stuffing or dictionary attack in progress."
        ),
        severity=rule.severity or "HIGH",
        status="DETECTED",
        category="Identity / Network",
        source="Correlation Engine (Auth Monitor)",
        source_ip=ip_address or "Unknown",
        target_system=f"Identity Gateway ({email})",
        assignee="Unassigned",
        risk_score=8.0 if rule.severity == "CRITICAL" else 7.0,
        tags=["brute-force", "credential-stuffing", "automated-detection", "auth-anomaly"],
        raw_logs=[
            {
                "time": now.strftime("%H:%M:%S"),
                "level": "WARN",
                "msg": f"Failed logins burst: {matching_failures} attempts in {window_minutes}m",
                "detail": f"Account: {email} | Source IP: {ip_address} | Rule: {rule.name}",
            }
        ],
        detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    # Add IOC
    if ip_address and ip_address not in ("Unknown", "127.0.0.1", ""):
        db.add(IOC(
            incident_id=incident.id,
            type="IP",
            value=ip_address,
            confidence=85.0,
            created_at=now,
        ))

    # Add in-app notification
    notif = Notification(
        title=f"ALERT: Brute-force detected on {email}",
        message=f"{matching_failures} failed logins from {ip_address}",
        color="#FF3366",
        severity="high",
        read=False,
        incident_id=incident.id,
        created_at=now,
    )
    db.add(notif)

    # Record rule execution
    rule.last_triggered_at = now
    exec_record = AutomationExecution(
        rule_id=rule.id,
        rule_name=rule.name,
        trigger_event="FAILED_LOGINS_BURST",
        incident_id=incident.id,
        status="ACTIONS_COMPLETED",
        outcome_details={
            "matching_failures": matching_failures,
            "window_minutes": window_minutes,
            "target_email": email,
            "source_ip": ip_address,
        },
        executed_at=now,
    )
    db.add(exec_record)
    db.commit()
    db.refresh(incident)

    # Broadcast WebSocket events
    try:
        await manager.broadcast("incident.created", {
            "id": incident.id,
            "public_id": incident.public_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "source": incident.source,
            "assignee": incident.assignee,
            "created_at": incident.created_at.isoformat(),
        })
        await manager.broadcast("notification.created", {
            "id": notif.id,
            "title": notif.title,
            "message": notif.message,
            "severity": notif.severity,
            "color": notif.color,
        })
    except Exception as e:
        logger.error(f"[CORRELATION] WebSocket broadcast error: {e}")

    # Dispatch Email Notification if configured
    if "SEND_EMAIL" in (rule.actions or ["SEND_EMAIL"]):
        recipients = settings.NOTIFICATION_RECIPIENTS or ["security@cybersentinel.ai"]
        for recipient in recipients:
            try:
                await send_security_email(
                    db=db,
                    recipient=recipient,
                    subject=f"[{incident.severity}] Brute-Force Alert: {matching_failures} Failed Logins on {email}",
                    event_title="Brute-Force Authentication Anomaly Detected",
                    severity=incident.severity,
                    reason=f"{matching_failures} authentication failures detected within {window_minutes} minutes.",
                    evidence=f"Target: {email}\nSource IP: {ip_address}\nDetected At: {now.isoformat()}\nRule: {rule.name}",
                    investigation_steps=[
                        "Inspect firewall/WAF logs for origin IP reputation",
                        "Verify whether user account password has been compromised",
                        "Enforce temporary lockout or step-up MFA challenge",
                        "Review active user sessions and terminate if suspicious",
                    ],
                    incident_public_id=incident.public_id,
                    incident_db_id=incident.id,
                    rule_id=rule.id,
                )
            except Exception as e:
                logger.error(f"[CORRELATION] Email dispatch error to {recipient}: {e}")

    return incident


async def evaluate_login_success(
    db: Session,
    email: str,
    ip_address: str,
) -> Optional[Incident]:
    """
    Detects suspicious login activity: a successful authentication
    immediately following multiple failed logins on the same account.
    """
    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.rule_type == "LOGIN_AFTER_FAILURES", DetectionRule.enabled == True)
        .order_by(DetectionRule.id.asc())
        .all()
    )
    if not rules:
        return None

    for rule in rules:
        if is_rule_in_cooldown(rule, account=email, db=db):
            logger.debug(f"[CORRELATION] Rule '{rule.name}' is in cooldown for account '{email}'; skipping.")
            continue

        conditions = rule.conditions or {}
        threshold = int(conditions.get("threshold", 3))
        window_minutes = int(conditions.get("window_minutes", 10))

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        failures_count = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "LOGIN_FAILED",
                AuditLog.user_email == email,
                AuditLog.timestamp >= cutoff,
            )
            .count()
        )

        if failures_count >= threshold:
            break
    else:
        return None

    if failures_count < threshold:
        return None

    logger.warning(
        f"[CORRELATION] Suspicious login detected: {email} succeeded after {failures_count} failures "
        f"from IP {ip_address} within {window_minutes}m"
    )

    now = datetime.now(timezone.utc)
    public_id = f"INC-2024-{uuid.uuid4().hex[:8].upper()}"

    # Create Incident
    incident = Incident(
        public_id=public_id,
        title=f"Suspicious Authentication: Login Succeeded After {failures_count} Failures ({email})",
        description=(
            f"Account '{email}' successfully authenticated from IP {ip_address} immediately "
            f"following {failures_count} failed login attempts within the preceding {window_minutes} minutes. "
            f"Confidence: 75%. Note: May represent legitimate user credential recovery or successful password guess."
        ),
        severity=rule.severity or "HIGH",
        status="DETECTED",
        category="Identity & Access",
        source="Correlation Engine (Auth Monitor)",
        source_ip=ip_address or "Unknown",
        target_system=f"User Session ({email})",
        assignee="Unassigned",
        risk_score=7.2,
        tags=["suspicious-login", "credential-guessing", "anomalous-auth", "identity"],
        raw_logs=[
            {
                "time": now.strftime("%H:%M:%S"),
                "level": "WARN",
                "msg": f"Success after {failures_count} failures",
                "detail": f"Account: {email} | IP: {ip_address} | Confidence: 75%",
            }
        ],
        detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    # Add IOC
    if ip_address and ip_address not in ("Unknown", "127.0.0.1", ""):
        db.add(IOC(
            incident_id=incident.id,
            type="IP",
            value=ip_address,
            confidence=75.0,
            created_at=now,
        ))

    notif = Notification(
        title=f"SUSPICIOUS LOGIN: {email}",
        message=f"Successful login following {failures_count} failed attempts",
        color="#FFAA00",
        severity="high",
        read=False,
        incident_id=incident.id,
        created_at=now,
    )
    db.add(notif)

    rule.last_triggered_at = now
    exec_record = AutomationExecution(
        rule_id=rule.id,
        rule_name=rule.name,
        trigger_event="LOGIN_AFTER_FAILURES",
        incident_id=incident.id,
        status="ACTIONS_COMPLETED",
        outcome_details={
            "preceding_failures": failures_count,
            "window_minutes": window_minutes,
            "account": email,
            "source_ip": ip_address,
        },
        executed_at=now,
    )
    db.add(exec_record)
    db.commit()
    db.refresh(incident)

    try:
        await manager.broadcast("incident.created", {
            "id": incident.id,
            "public_id": incident.public_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "source": incident.source,
            "assignee": incident.assignee,
            "created_at": incident.created_at.isoformat(),
        })
        await manager.broadcast("notification.created", {
            "id": notif.id,
            "title": notif.title,
            "message": notif.message,
            "severity": notif.severity,
            "color": notif.color,
        })
    except Exception as e:
        logger.error(f"[CORRELATION] WebSocket broadcast error: {e}")

    # Dispatch email
    if "SEND_EMAIL" in (rule.actions or ["SEND_EMAIL"]):
        recipients = settings.NOTIFICATION_RECIPIENTS or ["security@cybersentinel.ai"]
        for recipient in recipients:
            try:
                await send_security_email(
                    db=db,
                    recipient=recipient,
                    subject=f"[{incident.severity}] Suspicious Login Alert: {email} Succeeded After {failures_count} Failures",
                    event_title="Suspicious Login Following Failed Attempts",
                    severity=incident.severity,
                    reason=f"Account authenticated after {failures_count} consecutive failed attempts within {window_minutes}m.",
                    evidence=f"Account: {email}\nSource IP: {ip_address}\nPreceding Failures: {failures_count}\nConfidence: 75% (Uncertainty: possible legitimate password re-try)",
                    investigation_steps=[
                        "Contact user via out-of-band channel to verify authentication authenticity",
                        "Inspect geographic location and ISP of origin IP",
                        "Check for unauthorized privilege escalation or data access during this session",
                        "Trigger 'Suspicious Login Detection & Response' playbook if unauthorized",
                    ],
                    incident_public_id=incident.public_id,
                    incident_db_id=incident.id,
                    rule_id=rule.id,
                )
            except Exception as e:
                logger.error(f"[CORRELATION] Email dispatch error: {e}")

    return incident


async def evaluate_incident_rules(
    db: Session,
    incident: Incident,
) -> List[DetectionRule]:
    """
    Evaluates an ingested or created incident against active DetectionRules
    (e.g., Critical Ingest, Privilege Escalation, Ransomware Outbreak).
    Dispatches automated emails to configured recipients when rules trigger.
    """
    enabled_rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    triggered_rules: List[DetectionRule] = []

    for rule in enabled_rules:
        if is_rule_in_cooldown(rule):
            continue

        matched = False
        conditions = rule.conditions or {}

        # 1. Match by Rule Type
        if rule.rule_type == "CRITICAL_INCIDENT_INGEST":
            matched = (incident.severity.upper() == "CRITICAL")
        elif rule.rule_type == "HIGH_SEVERITY_ALERT":
            matched = (incident.severity.upper() in ("HIGH", "CRITICAL"))
        elif rule.rule_type == "CUSTOM":
            target_cat = conditions.get("category")
            if target_cat and target_cat.lower() in incident.category.lower():
                matched = True
            elif conditions.get("severity") and conditions.get("severity").upper() == incident.severity.upper():
                matched = True

        # Check category match override if specified in conditions
        if not matched and "categories" in conditions:
            cat_list = [c.lower() for c in conditions["categories"]]
            if any(c in incident.category.lower() for c in cat_list):
                matched = True

        if not matched:
            continue

        # Rule matched and not in cooldown!
        logger.info(f"[CORRELATION] Incident {incident.public_id} matched rule '{rule.name}' ({rule.rule_type})")
        now = datetime.now(timezone.utc)
        rule.last_triggered_at = now

        exec_record = AutomationExecution(
            rule_id=rule.id,
            rule_name=rule.name,
            trigger_event=f"INCIDENT_INGEST:{incident.severity}:{incident.category}",
            incident_id=incident.id,
            status="ACTIONS_COMPLETED",
            outcome_details={
                "incident_public_id": incident.public_id,
                "incident_title": incident.title,
                "severity": incident.severity,
                "category": incident.category,
            },
            executed_at=now,
        )
        db.add(exec_record)
        triggered_rules.append(rule)

        # Dispatch email if SEND_EMAIL action is present
        if "SEND_EMAIL" in (rule.actions or ["SEND_EMAIL"]):
            recipients = settings.NOTIFICATION_RECIPIENTS or ["security@cybersentinel.ai"]
            for recipient in recipients:
                try:
                    await send_security_email(
                        db=db,
                        recipient=recipient,
                        subject=f"[{incident.severity}] Security Alert: {incident.title}",
                        event_title=f"Rule Triggered: {rule.name}",
                        severity=incident.severity,
                        reason=f"Incident {incident.public_id} triggered rule '{rule.name}' based on {incident.category} / {incident.severity}.",
                        evidence=(
                            f"Incident: {incident.public_id} — {incident.title}\n"
                            f"Severity: {incident.severity} | Category: {incident.category}\n"
                            f"Target System: {incident.target_system}\n"
                            f"Source IP: {incident.source_ip}\n"
                            f"Description: {incident.description}"
                        ),
                        investigation_steps=[
                            f"Open Incident {incident.public_id} in CyberSentinel SOC Dashboard",
                            "Run automated AI Triage to extract MITRE ATT&CK techniques & IOCs",
                            "Review recommended defensive playbooks for immediate containment",
                        ],
                        incident_public_id=incident.public_id,
                        incident_db_id=incident.id,
                        rule_id=rule.id,
                    )
                except Exception as e:
                    logger.error(f"[CORRELATION] Failed to dispatch incident email to {recipient}: {e}")

    if triggered_rules:
        db.commit()

    return triggered_rules
