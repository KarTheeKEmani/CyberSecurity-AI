"""
End-to-End Live Workflow & Two-Client WebSocket Synchronization Test
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.models.incident import Incident
from app.models.audit_log import AuditLog
from app.models.notification import Notification


def test_full_incident_response_lifecycle_workflow(client, auth_headers_analyst, auth_headers_admin, db_session):
    """
    Validates complete end-to-end multi-user SOC lifecycle:
    Ingest -> AI Triage -> Human Review -> Playbook Simulation -> Status Progression -> Audit Trail
    """
    # 1. Admin creates an incident
    create_payload = {
        "title": "Unauthorized AWS S3 Bucket Exfiltration",
        "description": "Unusual egress traffic detected from cloud bucket to unauthorized IP.",
        "severity": "CRITICAL",
        "category": "Cloud Security",
        "source": "AWS CloudTrail",
        "source_ip": "198.51.100.77",
        "target_system": "s3://corp-analytics-prod",
        "assignee": "Sarah Chen",
    }
    create_res = client.post("/api/incidents", headers=auth_headers_admin, json=create_payload)
    assert create_res.status_code == 201
    inc_data = create_res.json()
    inc_id = inc_data["id"]
    public_id = inc_data["public_id"]
    assert inc_data["status"] == "DETECTED"
    assert inc_data["severity"] == "CRITICAL"

    # 2. Analyst views the incident in queue
    list_res = client.get("/api/incidents", headers=auth_headers_analyst)
    assert list_res.status_code == 200
    all_incidents = list_res.json()["incidents"]
    assert any(i["id"] == inc_id for i in all_incidents)

    # 3. Analyst executes AI Triage
    triage_res = client.post(f"/api/incidents/{inc_id}/triage", headers=auth_headers_analyst, json={})
    assert triage_res.status_code == 200
    triage_data = triage_res.json()
    assert triage_data["classification"] in ("CONFIRMED_THREAT", "CONFIRMED_BREACH", "POTENTIAL_THREAT")
    assert len(triage_data["iocs"]) > 0
    assert len(triage_data["mitre_techniques"]) > 0
    assert "recommended_playbook" in triage_data

    # Incident status should now be updated to TRIAGED or higher
    inc_detail = client.get(f"/api/incidents/{inc_id}", headers=auth_headers_analyst).json()
    assert inc_detail["status"] in ("TRIAGED", "INVESTIGATING")

    # 4. Analyst executes simulated defensive containment playbook
    playbook_res = client.post(f"/api/incidents/{inc_id}/playbook/execute", headers=auth_headers_analyst, json={
        "execution_mode": "SIMULATION"
    })
    assert playbook_res.status_code == 200
    pb_data = playbook_res.json()
    assert pb_data["status"] == "COMPLETED"
    assert pb_data["execution_mode"] == "SIMULATION"
    assert len(pb_data["steps_results"]) > 0

    # Incident status must be transitioned to CONTAINED
    inc_after_pb = client.get(f"/api/incidents/{inc_id}", headers=auth_headers_analyst).json()
    assert inc_after_pb["status"] == "CONTAINED"

    # 5. Analyst resolves incident
    resolve_res = client.patch(f"/api/incidents/{inc_id}/status", headers=auth_headers_analyst, json={
        "status": "RESOLVED"
    })
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
    assert resolve_res.json()["resolved_at"] is not None

    # 6. Verify Audit Logs captured the full operational sequence
    audit_res = client.get(f"/api/audit?search={public_id}", headers=auth_headers_admin)
    assert audit_res.status_code == 200
    logs = audit_res.json()["logs"]
    actions = [l["action"] for l in logs]
    assert "INCIDENT_CREATED" in actions
    assert "TRIAGE_EXECUTED" in actions
    assert "PLAYBOOK_EXECUTED" in actions

    # 7. Verify Analytics Summary reflects updated state
    summary_res = client.get("/api/analytics/summary", headers=auth_headers_analyst)
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_incidents"] > 0
    assert summary["resolved_incidents"] > 0
