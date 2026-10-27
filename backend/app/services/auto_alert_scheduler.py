"""
Auto-Alert Scheduler — generates a random simulated security alert every N seconds
and dispatches email notifications to all configured NOTIFICATION_RECIPIENTS.

This module is started once during the app lifespan (startup) and runs as a
persistent asyncio background task for the lifetime of the process.

Phase 4 additions:
  - Runtime configurable interval (set_interval)
  - Pause / Resume without killing the background task
  - Rich state snapshot returned by get_state()
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.alert_generator import generate_mock_alert
from app.services.email_service import send_security_email
from app.realtime.connection_manager import manager

logger = logging.getLogger("auto_alert_scheduler")

# ---------------------------------------------------------------------------
# Internal state (in-process only; resets on restart)
# ---------------------------------------------------------------------------
_state = {
    "running": False,       # True when the background task is alive
    "paused": False,        # True when running but not firing (pause mode)
    "task": None,           # asyncio.Task reference
    "total_generated": 0,
    "last_generated_at": None,
    "next_fire_at": None,
    # Runtime-overridable interval (falls back to settings value)
    "_interval_override": None,
}


def _effective_interval() -> int:
    """Return the currently active interval in seconds."""
    return _state["_interval_override"] or settings.AUTO_ALERT_INTERVAL_SECONDS


def get_state() -> dict:
    """Return a serialisable snapshot of scheduler state."""
    return {
        "running": _state["running"],
        "paused": _state["paused"],
        "interval_seconds": _effective_interval(),
        "total_generated": _state["total_generated"],
        "last_generated_at": (
            _state["last_generated_at"].isoformat()
            if _state["last_generated_at"] else None
        ),
        "next_fire_at": (
            _state["next_fire_at"].isoformat()
            if _state["next_fire_at"] else None
        ),
        "recipients": settings.NOTIFICATION_RECIPIENTS,
        "email_demo_mode": settings.EMAIL_DEMO_MODE,
        "email_enabled": settings.EMAIL_ENABLED,
    }


def set_interval(seconds: int) -> dict:
    """
    Update the firing interval at runtime without restarting the task.
    The new interval takes effect after the current sleep finishes.
    Valid range: 10–3600 seconds.
    """
    if not (10 <= seconds <= 3600):
        raise ValueError("Interval must be between 10 and 3600 seconds.")
    _state["_interval_override"] = seconds
    logger.info(f"[AUTO-SCHEDULER] Interval updated to {seconds}s at runtime.")
    return get_state()


def pause_scheduler() -> dict:
    """Pause the scheduler (task stays alive but won't fire alerts)."""
    _state["paused"] = True
    _state["next_fire_at"] = None
    logger.info("[AUTO-SCHEDULER] Paused.")
    return get_state()


def resume_scheduler() -> dict:
    """Resume the scheduler after a pause."""
    _state["paused"] = False
    logger.info("[AUTO-SCHEDULER] Resumed.")
    return get_state()


async def _fire_alert() -> Optional[dict]:
    """
    Generate one random alert, broadcast via WebSocket, and email every recipient.
    """
    db = SessionLocal()
    try:
        incident = generate_mock_alert(db, created_by="AUTO_SCHEDULER")
        _state["total_generated"] += 1
        _state["last_generated_at"] = datetime.now(timezone.utc)

        logger.info(
            f"[AUTO-SCHEDULER] Alert #{_state['total_generated']}: "
            f"{incident.public_id} ({incident.severity}) — {incident.title[:60]}"
        )

        # Broadcast WebSocket
        try:
            await manager.broadcast("incident.created", {
                "id": incident.id,
                "public_id": incident.public_id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "source": incident.source,
                "assignee": incident.assignee,
                "is_simulated": True,
                "auto_generated": True,
                "created_at": incident.created_at.isoformat(),
            })
        except Exception as ws_err:
            logger.warning(f"[AUTO-SCHEDULER] WebSocket broadcast failed: {ws_err}")

        # Email notifications
        recipients = settings.NOTIFICATION_RECIPIENTS or []
        if not recipients:
            logger.warning("[AUTO-SCHEDULER] No NOTIFICATION_RECIPIENTS — skipping email.")
        else:
            raw = incident.raw_logs[0] if incident.raw_logs else {}
            interval_used = _effective_interval()
            evidence = "\n".join([
                f"Incident ID  : {incident.public_id}",
                f"Severity     : {incident.severity}",
                f"Category     : {incident.category}",
                f"Source       : {incident.source}",
                f"Source IP    : {incident.source_ip or 'N/A'}",
                f"Target System: {incident.target_system or 'N/A'}",
                f"Detection    : {raw.get('detection_reason', 'Automated pattern match')}",
                f"Generated at : {incident.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"Auto-Scheduled: Every {interval_used}s",
            ])

            investigation_steps = [
                "Verify the source IP against threat intelligence feeds.",
                "Review authentication logs for the flagged user/system.",
                "Isolate the target system if critical indicators are confirmed.",
                "Escalate to senior analyst if activity cannot be explained.",
                "Update incident status and document findings in the CyberSentinel dashboard.",
            ]

            subject = f"[CyberSentinel AI] \U0001F6A8 {incident.severity} Alert — {incident.title[:60]}"

            for recipient in recipients:
                try:
                    await send_security_email(
                        db=db,
                        recipient=recipient,
                        subject=subject,
                        event_title=incident.title,
                        severity=incident.severity,
                        reason=(
                            f"Automated alert generated by CyberSentinel AI scheduler "
                            f"(fires every {interval_used}s)"
                        ),
                        evidence=evidence,
                        investigation_steps=investigation_steps,
                        incident_public_id=incident.public_id,
                        incident_db_id=incident.id,
                        dashboard_url="http://localhost:3000/dashboard.html",
                    )
                    logger.info(f"[AUTO-SCHEDULER] Email → {recipient} for {incident.public_id}")
                except Exception as mail_err:
                    logger.error(f"[AUTO-SCHEDULER] Email to {recipient} failed: {mail_err}")

        return {"public_id": incident.public_id, "severity": incident.severity}

    except Exception as e:
        logger.error(f"[AUTO-SCHEDULER] Error: {e}", exc_info=True)
        return None
    finally:
        db.close()


async def _scheduler_loop():
    """
    Infinite loop: check paused state, optionally fire an alert, sleep, repeat.
    Supports runtime interval changes — effective after the current sleep cycle.
    """
    logger.info(
        f"[AUTO-SCHEDULER] Started — interval={_effective_interval()}s, "
        f"recipients={settings.NOTIFICATION_RECIPIENTS}"
    )
    # Short startup delay so DB is fully ready
    await asyncio.sleep(5)

    while True:
        if _state["paused"]:
            # While paused: poll every 2 s so we react quickly to a resume
            _state["next_fire_at"] = None
            await asyncio.sleep(2)
            continue

        _state["next_fire_at"] = datetime.now(timezone.utc)
        await _fire_alert()

        interval = _effective_interval()
        _state["next_fire_at"] = datetime.now(timezone.utc) + timedelta(seconds=interval)
        await asyncio.sleep(interval)


def start_scheduler():
    """Create and register the background asyncio task. Call once at startup."""
    if _state["running"]:
        logger.warning("[AUTO-SCHEDULER] Already running.")
        return

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Fallback for non-async context (e.g. called at startup before loop exists)
        loop = asyncio.get_event_loop()

    task = loop.create_task(_scheduler_loop(), name="auto_alert_scheduler")
    _state["running"] = True
    _state["paused"] = False
    _state["task"] = task

    def _on_done(t: asyncio.Task):
        _state["running"] = False
        _state["paused"] = False
        _state["task"] = None
        if not t.cancelled():
            exc = t.exception()
            if exc:
                logger.error(f"[AUTO-SCHEDULER] Task crashed: {exc}", exc_info=exc)

    task.add_done_callback(_on_done)
    logger.info("[AUTO-SCHEDULER] Background task registered.")


def stop_scheduler():
    """Cancel the running scheduler task."""
    task = _state.get("task")
    if task and not task.done():
        task.cancel()
        _state["running"] = False
        _state["paused"] = False
        logger.info("[AUTO-SCHEDULER] Cancelled.")
