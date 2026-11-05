"""
Mock Alert Generator Service — Realistic Security Event Simulation
All generated events are clearly labelled SIMULATED.
"""
import uuid
import random
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.notification import Notification
from app.models.ioc import IOC

logger = logging.getLogger("alert_generator")

SIMULATED_IPS = [
    "185.220.101.45", "91.121.87.220", "198.211.11.7", "103.248.12.44",
    "45.155.204.127", "79.110.62.100", "185.56.80.65", "194.165.16.0",
    "192.168.1.210",  # internal
]

SIMULATED_USERS = [
    "john.doe@example.com", "admin@corp.local", "service_account", "root",
    "webmaster@company.org", "backup_user@internal",
]

SIMULATED_SYSTEMS = [
    "WEB-SERVER-01", "DB-MASTER-01", "VPN-GW-02", "WKSTN-DEV-012",
    "MAIL-SERVER-01", "AUTH-SVCS-01", "CORE-ROUTER-01", "API-GW-PROD",
]

EVENT_TEMPLATES = {
    "REPEATED_FAILED_LOGINS": {
        "severity": "HIGH",
        "category": "Authentication Failure",
        "source": "SIEM (Splunk)",
        "title_tpl": "Repeated Failed Logins Detected — {user} ({count} attempts)",
        "desc_tpl": (
            "[SIMULATED] {count} failed authentication attempts detected for account '{user}' "
            "from IP {ip} within the last {window} minutes. "
            "Detection reason: Credential-stuffing or brute-force pattern detected by SIEM rule AUTH-BF-001."
        ),
        "detection_reason": "Burst of failed authentication events exceeding threshold within time window",
    },
    "SUSPICIOUS_LOGIN_AFTER_FAILURES": {
        "severity": "CRITICAL",
        "category": "Suspicious Authentication",
        "source": "EDR (CrowdStrike)",
        "title_tpl": "Suspicious Successful Login After Multiple Failures — {user}",
        "desc_tpl": (
            "[SIMULATED] A successful login for account '{user}' from IP {ip} was recorded "
            "immediately after {count} consecutive failed attempts. "
            "Detection reason: Pattern consistent with successful brute-force or credential-stuffing attack."
        ),
        "detection_reason": "Successful login following multiple failed attempts from same source IP",
    },
    "UNUSUAL_LOCATION": {
        "severity": "MEDIUM",
        "category": "Geo-Anomaly Authentication",
        "source": "SIEM (Splunk)",
        "title_tpl": "Login From Unusual Geographic Location — {user}",
        "desc_tpl": (
            "[SIMULATED] Authentication for '{user}' detected from IP {ip} "
            "which is geographically inconsistent with the user's typical login pattern. "
            "Detection reason: Geo-velocity anomaly flagged by baseline behavioral analytics. "
            "Note: This does NOT confirm malicious activity; may be a VPN or travel scenario."
        ),
        "detection_reason": "Source IP geographic location inconsistent with user baseline",
    },
    "UNUSUAL_LOGIN_TIME": {
        "severity": "MEDIUM",
        "category": "Temporal Anomaly Authentication",
        "source": "SIEM (Splunk)",
        "title_tpl": "Login at Unusual Time — {user}",
        "desc_tpl": (
            "[SIMULATED] Authentication for '{user}' from {system} occurred at an unusual hour "
            "outside the user's established activity baseline (e.g., 02:30 AM on a weekday). "
            "Detection reason: Time-based behavioral anomaly."
        ),
        "detection_reason": "Authentication outside established user time baseline",
    },
    "BRUTE_FORCE": {
        "severity": "CRITICAL",
        "category": "Brute-Force Attack",
        "source": "WAF (Cloudflare)",
        "title_tpl": "Possible Brute-Force Attack Detected — {system}",
        "desc_tpl": (
            "[SIMULATED] High-volume automated credential attack detected against {system} "
            "from source IP {ip}. {count} authentication requests recorded in {window} seconds. "
            "Detection reason: Request rate exceeds human-possible authentication speed by 10x."
        ),
        "detection_reason": "Automated high-speed authentication request rate exceeding human threshold",
    },
    "SUSPICIOUS_NETWORK": {
        "severity": "HIGH",
        "category": "Network Anomaly",
        "source": "Firewall (Palo Alto)",
        "title_tpl": "Suspicious Outbound Network Connection — {system}",
        "desc_tpl": (
            "[SIMULATED] Unusual outbound network connection detected from {system} to external IP {ip} "
            "on non-standard port. Traffic volume: anomalous. "
            "Detection reason: Behavioral baseline deviation — possible C2 communication or data exfiltration."
        ),
        "detection_reason": "Anomalous outbound connection to non-whitelisted external endpoint",
    },
    "PRIVILEGED_LOGIN": {
        "severity": "HIGH",
        "category": "Privileged Access",
        "source": "SIEM (Splunk)",
        "title_tpl": "Privileged Account Login Detected — {user}",
        "desc_tpl": (
            "[SIMULATED] A privileged administrative account '{user}' logged in from {system} at {time}. "
            "Detection reason: Privileged account activity baseline monitoring. "
            "This is an informational alert; verify with the account holder if activity was expected."
        ),
        "detection_reason": "Privileged account authentication recorded by access monitoring",
    },
    "UNUSUAL_ACCOUNT_ACTIVITY": {
        "severity": "MEDIUM",
        "category": "Behavioral Anomaly",
        "source": "UEBA",
        "title_tpl": "Unusual Account Activity Detected — {user}",
        "desc_tpl": (
            "[SIMULATED] User account '{user}' exhibited unusual behavioral patterns: "
            "abnormal data access volume, access to resources outside normal scope, or unusual process execution. "
            "Detection reason: UEBA anomaly score exceeded 85th percentile threshold."
        ),
        "detection_reason": "UEBA score exceeded anomaly threshold based on behavioral baseline",
    },
    "CRITICAL_INCIDENT": {
        "severity": "CRITICAL",
        "category": "Critical Security Incident",
        "source": "EDR (CrowdStrike)",
        "title_tpl": "Critical Security Incident — Malware Activity on {system}",
        "desc_tpl": (
            "[SIMULATED] Critical security event detected on {system}: "
            "Suspicious process execution chain, possible malware activity, "
            "unusual memory injection patterns observed. Source IP: {ip}. "
            "Detection reason: Multi-signal correlation across EDR, SIEM, and network telemetry."
        ),
        "detection_reason": "Multi-signal correlation across EDR, network, and process telemetry",
    },
}


def generate_mock_alert(
    db: Session,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    created_by: str = "MOCK_GENERATOR",
) -> Incident:
    """
    Generate a single realistic SIMULATED security alert and persist to database.
    Every generated event is clearly labelled [SIMULATED] in title, description, and tags.
    """
    # Choose event template
    if category and category in EVENT_TEMPLATES:
        event_key = category
    else:
        event_key = random.choice(list(EVENT_TEMPLATES.keys()))

    template = EVENT_TEMPLATES[event_key]

    # Override severity if specified
    chosen_severity = severity.upper() if severity else template["severity"]
    if chosen_severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        chosen_severity = template["severity"]

    ip = random.choice(SIMULATED_IPS)
    user = random.choice(SIMULATED_USERS)
    system = random.choice(SIMULATED_SYSTEMS)
    count = random.randint(5, 50)
    window = random.randint(2, 15)
    time_str = datetime.now(timezone.utc).strftime("%H:%M UTC")

    title = template["title_tpl"].format(
        user=user, ip=ip, system=system, count=count, window=window
    )
    description = template["desc_tpl"].format(
        user=user, ip=ip, system=system, count=count, window=window, time=time_str
    )

    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex[:8].upper()
    public_id = f"SIM-{now.strftime('%Y')}-{suffix}"

    risk_map = {"CRITICAL": 9.2, "HIGH": 7.5, "MEDIUM": 4.8, "LOW": 2.0}

    incident = Incident(
        public_id=public_id,
        title=f"[SIMULATED] {title}",
        description=description,
        severity=chosen_severity,
        status="DETECTED",
        category=template["category"],
        source=template["source"],
        source_ip=ip,
        destination_ip=None,
        target_system=system,
        assignee="Unassigned",
        risk_score=risk_map.get(chosen_severity, 5.0),
        tags=["SIMULATED", event_key, f"generator:{created_by}"],
        raw_logs=[
            {
                "time": now.strftime("%H:%M:%S"),
                "level": "WARN",
                "msg": "[SIMULATED] Mock alert generated by CyberSentinel test engine",
                "event_type": event_key,
                "source_ip": ip,
                "target": system,
                "detection_reason": template["detection_reason"],
                "is_simulated": True,
            }
        ],
        detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()

    # Add IOC
    if ip and ip not in ("Unknown", "None", ""):
        db.add(IOC(
            incident_id=incident.id,
            type="IP",
            value=ip,
            confidence=70.0,  # Simulated — lower confidence
            created_at=now,
        ))

    # Notification
    color_map = {"CRITICAL": "#FF3366", "HIGH": "#FF8800", "MEDIUM": "#FFAA00", "LOW": "#00D4FF"}
    notif = Notification(
        title=f"[SIM] {chosen_severity}: {title[:50]}",
        message=f"Simulated alert on {system} — {template['category']}",
        color=color_map.get(chosen_severity, "#00D4FF"),
        severity=chosen_severity.lower(),
        read=False,
        incident_id=incident.id,
        created_at=now,
    )
    db.add(notif)
    db.commit()
    db.refresh(incident)

    logger.info(f"[MOCK GENERATOR] Created simulated alert: {incident.public_id} ({chosen_severity})")
    return incident


def generate_batch(
    db: Session,
    count: int = 5,
    category: Optional[str] = None,
    severity: Optional[str] = None,
) -> list:
    """Generate a controlled batch of simulated alerts (max 20 per call)."""
    count = min(count, 20)
    incidents = []
    for _ in range(count):
        inc = generate_mock_alert(db, category=category, severity=severity)
        incidents.append(inc)
    return incidents
