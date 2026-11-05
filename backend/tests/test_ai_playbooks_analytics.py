"""
AI Triage, Playbook Simulations, Analytics & Audit Tests
"""
import pytest


def test_ai_triage_incident(client, auth_headers_analyst):
    """Test AI triage execution stores analysis telemetry and updates incident status."""
    res = client.post("/api/incidents/1/triage", headers=auth_headers_analyst, json={})
    assert res.status_code == 200
    data = res.json()
    assert "classification" in data
    assert "severity_score" in data
    assert "confidence" in data
    assert "root_cause" in data
    assert "iocs" in data
    assert len(data["iocs"]) > 0
    assert "mitre_techniques" in data
    assert len(data["mitre_techniques"]) > 0


def test_playbook_simulation_execution(client, auth_headers_analyst):
    """Test responsible playbook simulation execution logs steps and updates status."""
    res = client.post("/api/incidents/1/playbook/execute", headers=auth_headers_analyst, json={
        "execution_mode": "SIMULATION"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["execution_mode"] == "SIMULATION"
    assert len(data["steps_results"]) > 0


def test_analytics_summary_database_driven(client, auth_headers_analyst):
    """Test analytics summary retrieves real aggregated stats from the database."""
    res = client.get("/api/analytics/summary", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.json()
    assert data["total_incidents"] >= 5
    assert data["critical_incidents"] >= 1
    assert "avg_mttr_hours" in data


def test_analytics_overview_structure(client, auth_headers_analyst):
    """Test full analytics trends and heatmap matrix."""
    res = client.get("/api/analytics/overview", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.json()
    assert "trends" in data
    assert "attack_vectors" in data
    assert "severity_dist" in data
    assert "heatmap" in data
    assert len(data["heatmap"]["systems"]) == 8


def test_audit_logging_integrity(client, auth_headers_admin):
    """Test audit log trail captures operational events."""
    res = client.get("/api/audit", headers=auth_headers_admin)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] > 0
    assert len(data["logs"]) > 0
    first_log = data["logs"][0]
    assert "public_id" in first_log
    assert "action" in first_log
    assert "user_email" in first_log


def test_api_key_lifecycle(client, auth_headers_admin):
    """Test API key creation reveals raw key once and stores only hash."""
    res = client.post("/api/api-keys", headers=auth_headers_admin, json={
        "name": "SIEM Automated Poller",
        "permissions": ["incidents:read"]
    })
    assert res.status_code == 201
    data = res.json()
    assert "raw_key" in data
    assert data["raw_key"].startswith("cs_live_")
    key_id = data["id"]

    # Listing API keys must NEVER return plaintext raw_key
    list_res = client.get("/api/api-keys", headers=auth_headers_admin)
    for k in list_res.json():
        assert "raw_key" not in k

    # Revoke API key
    del_res = client.delete(f"/api/api-keys/{key_id}", headers=auth_headers_admin)
    assert del_res.status_code == 200
