"""
Incident Management & Lifecycle Validation Test Suite
"""
import pytest


def test_list_incidents(client, auth_headers_analyst):
    """Test incident listing and pagination."""
    res = client.get("/api/incidents?page=1&page_size=10", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.json()
    assert "incidents" in data
    assert len(data["incidents"]) > 0
    assert data["total"] >= len(data["incidents"])


def test_create_incident(client, auth_headers_analyst):
    """Test creating an incident persists to DB with unique public ID."""
    payload = {
        "title": "Cobalt Strike Beaconing on Web DMZ",
        "description": "Observed outbound HTTPS beaconing to unclassified foreign IP.",
        "severity": "CRITICAL",
        "category": "C2 Beacon",
        "source": "EDR (CrowdStrike)",
        "source_ip": "198.51.100.24",
        "target_system": "DMZ-WEB-01",
        "assignee": "Sarah Chen",
    }
    res = client.post("/api/incidents", headers=auth_headers_analyst, json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["public_id"].startswith("INC-2024-")
    assert data["title"] == payload["title"]
    assert data["status"] == "DETECTED"


def test_valid_incident_lifecycle_transitions(client, auth_headers_analyst):
    """Test valid sequential status transitions: DETECTED → TRIAGED → INVESTIGATING → RESOLVED."""
    # Create incident
    res = client.post("/api/incidents", headers=auth_headers_analyst, json={
        "title": "Lifecycle Test Incident",
        "severity": "HIGH",
    })
    inc_id = res.json()["id"]

    # Transition 1: DETECTED -> TRIAGED
    res = client.patch(f"/api/incidents/{inc_id}/status", headers=auth_headers_analyst, json={"status": "TRIAGED"})
    assert res.status_code == 200
    assert res.json()["status"] == "TRIAGED"

    # Transition 2: TRIAGED -> INVESTIGATING
    res = client.patch(f"/api/incidents/{inc_id}/status", headers=auth_headers_analyst, json={"status": "INVESTIGATING"})
    assert res.status_code == 200
    assert res.json()["status"] == "INVESTIGATING"

    # Transition 3: INVESTIGATING -> RESOLVED
    res = client.patch(f"/api/incidents/{inc_id}/status", headers=auth_headers_analyst, json={"status": "RESOLVED"})
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"
    assert res.json()["resolved_at"] is not None


def test_invalid_lifecycle_transition_rejected(client, auth_headers_analyst):
    """Test rejecting invalid transitions (e.g. DETECTED directly to ERADICATED)."""
    res = client.post("/api/incidents", headers=auth_headers_analyst, json={
        "title": "Invalid Transition Test",
        "severity": "LOW",
    })
    inc_id = res.json()["id"]

    # DETECTED -> ERADICATED is invalid
    res = client.patch(f"/api/incidents/{inc_id}/status", headers=auth_headers_analyst, json={"status": "ERADICATED"})
    assert res.status_code == 400
    assert "Invalid lifecycle transition" in res.json()["detail"]


def test_search_and_filter_incidents(client, auth_headers_analyst):
    """Test filtering incidents by severity and search query."""
    res = client.get("/api/incidents?severity=critical&search=Ransomware", headers=auth_headers_analyst)
    assert res.status_code == 200
    data = res.json()
    for inc in data["incidents"]:
        assert inc["severity"] == "CRITICAL"
        assert "ransomware" in (inc["title"] + inc["description"]).lower()
