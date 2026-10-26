"""
Email Notification Service — SMTP delivery with demo/live modes, cooldown, and deduplication.
"""
import asyncio
import logging
import smtplib
import uuid
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.email_log import EmailLog
from app.models.rule import DetectionRule  # noqa – for type hints

logger = logging.getLogger("email_service")


def _send_smtp(
    to_address: str,
    subject: str,
    body_html: str,
) -> tuple[bool, str]:
    """
    Send email via SMTP.  Returns (success: bool, provider_response: str).
    Does NOT log credentials to output.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM_ADDRESS}>"
        msg["To"] = to_address

        part = MIMEText(body_html, "html")
        msg.attach(part)

        if settings.SMTP_USE_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)

        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)

        server.sendmail(settings.EMAIL_FROM_ADDRESS, [to_address], msg.as_string())
        server.quit()
        return True, "SMTP accepted"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed — check SMTP_USERNAME and SMTP_PASSWORD"
    except smtplib.SMTPRecipientsRefused:
        return False, f"Recipient refused: {to_address}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {type(e).__name__}"
    except Exception as e:
        return False, f"Delivery error: {type(e).__name__}"


def _build_html_body(
    event_title: str,
    severity: str,
    timestamp: datetime,
    incident_id: Optional[str],
    reason: str,
    evidence: str,
    investigation_steps: List[str],
    dashboard_url: str,
    is_simulation: bool,
) -> str:
    sim_banner = (
        '<div style="background:#ff9800;color:#fff;padding:10px;text-align:center;font-weight:bold;">'
        '⚠ EMAIL SIMULATION — This is a demo notification. No real email was sent in demo mode.'
        '</div>'
    ) if is_simulation else ""

    steps_html = "".join(f"<li>{s}</li>" for s in investigation_steps)
    sev_color = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d", "LOW": "#388e3c"}.get(severity.upper(), "#555")

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0;">
{sim_banner}
<div style="max-width:600px;margin:24px auto;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;">
  <div style="background:{sev_color};padding:16px 24px;">
    <h2 style="color:#fff;margin:0;">🚨 {event_title}</h2>
    <span style="background:rgba(0,0,0,0.3);color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;">{severity}</span>
  </div>
  <div style="padding:24px;">
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
      <tr><td style="padding:6px 0;color:#8b949e;width:140px;">Timestamp</td><td style="color:#c9d1d9;">{timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
      {'<tr><td style="padding:6px 0;color:#8b949e;">Incident ID</td><td style="color:#c9d1d9;">' + incident_id + '</td></tr>' if incident_id else ''}
      <tr><td style="padding:6px 0;color:#8b949e;">Alert Reason</td><td style="color:#c9d1d9;">{reason}</td></tr>
    </table>
    <h3 style="color:#58a6ff;margin-bottom:8px;">Evidence</h3>
    <pre style="background:#0d1117;padding:12px;border-radius:4px;color:#c9d1d9;font-size:12px;overflow-x:auto;">{evidence}</pre>
    <h3 style="color:#58a6ff;margin-bottom:8px;">Recommended Steps</h3>
    <ol style="color:#c9d1d9;padding-left:20px;">{steps_html}</ol>
    <div style="margin-top:24px;text-align:center;">
      <a href="{dashboard_url}" style="background:#1f6feb;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">View in Dashboard →</a>
    </div>
  </div>
  <div style="padding:12px 24px;background:#0d1117;text-align:center;font-size:11px;color:#8b949e;">
    CyberSentinel AI — Automated Security Notification{'&nbsp;&nbsp;|&nbsp;&nbsp;SIMULATION MODE' if is_simulation else ''}
  </div>
</div>
</body>
</html>
"""


async def send_security_email(
    db: Session,
    recipient: str,
    subject: str,
    event_title: str,
    severity: str,
    reason: str,
    evidence: str,
    investigation_steps: List[str],
    incident_public_id: Optional[str] = None,
    incident_db_id: Optional[int] = None,
    rule_id: Optional[int] = None,
    dashboard_url: str = "http://localhost:8000",
) -> EmailLog:
    """
    Send (or simulate) a security notification email.
    Always records an EmailLog entry regardless of delivery mode.
    """
    now = datetime.now(timezone.utc)
    is_simulation = settings.EMAIL_DEMO_MODE or not settings.EMAIL_ENABLED

    body_html = _build_html_body(
        event_title=event_title,
        severity=severity,
        timestamp=now,
        incident_id=incident_public_id,
        reason=reason,
        evidence=evidence,
        investigation_steps=investigation_steps,
        dashboard_url=dashboard_url,
        is_simulation=is_simulation,
    )

    log = EmailLog(
        public_id=f"EML-{uuid.uuid4().hex[:10].upper()}",
        rule_id=rule_id,
        incident_id=incident_db_id,
        recipient=recipient,
        subject=subject,
        body_text=body_html,
        status="SIMULATED" if is_simulation else "QUEUED",
        is_simulation=is_simulation,
        retry_count=0,
        created_at=now,
    )
    db.add(log)
    db.flush()

    if is_simulation:
        log.status = "SIMULATED"
        log.provider_response = "Email simulation recorded — not sent (demo mode active)"
        log.sent_at = now
        db.commit()
        logger.info(f"[EMAIL SIMULATION] To={recipient} Subject={subject}")
    else:
        # Attempt real delivery in background
        loop = asyncio.get_event_loop()
        success, provider_resp = await loop.run_in_executor(
            None, _send_smtp, recipient, subject, body_html
        )
        log.status = "DELIVERED" if success else "FAILED"
        log.provider_response = provider_resp
        log.sent_at = now if success else None
        log.retry_count = 0
        db.commit()
        if success:
            logger.info(f"[EMAIL SENT] To={recipient} Subject={subject}")
        else:
            logger.warning(f"[EMAIL FAILED] To={recipient}: {provider_resp}")

    db.refresh(log)
    return log


def check_email_cooldown(
    db: Session,
    rule_id: int,
    cooldown_minutes: int,
) -> bool:
    """Return True if cooldown has elapsed (OK to send), False if still cooling down."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
    recent = db.query(EmailLog).filter(
        EmailLog.rule_id == rule_id,
        EmailLog.created_at >= cutoff,
    ).first()
    return recent is None
