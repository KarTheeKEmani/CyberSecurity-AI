"""
Tests for: Chatbot, Alert Generator, Email Notifications, Detection Rules
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

ADMIN_TOKEN = None
ANALYST_TOKEN = None
VIEWER_TOKEN = None


def get_admin_token():
    global ADMIN_TOKEN
    if ADMIN_TOKEN:
        return ADMIN_TOKEN
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.ai", "password": "Password123!"})
    assert r.status_code == 200
    ADMIN_TOKEN = r.json()["access_token"]
    return ADMIN_TOKEN


def get_analyst_token():
    global ANALYST_TOKEN
    if ANALYST_TOKEN:
        return ANALYST_TOKEN
    r = client.post("/api/auth/login", json={"email": "sarah.chen@cybersentinel.ai", "password": "Password123!"})
    assert r.status_code == 200
    ANALYST_TOKEN = r.json()["access_token"]
    return ANALYST_TOKEN


def get_viewer_token():
    global VIEWER_TOKEN
    if VIEWER_TOKEN:
        return VIEWER_TOKEN
    r = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.ai", "password": "Password123!"})
    assert r.status_code == 200
    VIEWER_TOKEN = r.json()["access_token"]
    return VIEWER_TOKEN


# ============================================================
# CHATBOT TESTS
# ============================================================

class TestChatbot:
    def test_basic_chat_creates_conversation(self):
        token = get_analyst_token()
        r = client.post(
            "/api/chatbot/chat",
            json={"message": "What are the latest incidents?"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "content" in data
        assert "conversation_id" in data
        assert isinstance(data["conversation_id"], int)
        assert "is_mock" in data

    def test_chat_mock_clearly_labelled(self):
        token = get_analyst_token()
        r = client.post(
            "/api/chatbot/chat",
            json={"message": "Explain the latest critical incident"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        # In demo/mock mode, is_mock must be True
        assert data["is_mock"] is True

    def test_chat_continues_conversation(self):
        token = get_analyst_token()
        # First message
        r1 = client.post(
            "/api/chatbot/chat",
            json={"message": "Why are logins flagged?"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r1.status_code == 200
        conv_id = r1.json()["conversation_id"]

        # Continue conversation
        r2 = client.post(
            "/api/chatbot/chat",
            json={"message": "What MITRE technique is relevant?", "conversation_id": conv_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200
        assert r2.json()["conversation_id"] == conv_id

    def test_chat_ownership_enforced(self):
        """One user cannot access another user's conversation."""
        analyst_token = get_analyst_token()
        viewer_token = get_viewer_token()

        # Analyst creates conversation
        r = client.post(
            "/api/chatbot/chat",
            json={"message": "Test ownership"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        conv_id = r.json()["conversation_id"]

        # Viewer tries to access analyst's conversation messages
        r2 = client.get(
            f"/api/chatbot/conversations/{conv_id}/messages",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r2.status_code == 404

    def test_chat_input_too_long_rejected(self):
        token = get_analyst_token()
        r = client.post(
            "/api/chatbot/chat",
            json={"message": "A" * 2001},  # Exceeds 2000 char limit
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_list_conversations(self):
        token = get_analyst_token()
        r = client.get(
            "/api/chatbot/conversations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_delete_conversation(self):
        token = get_analyst_token()
        r = client.post(
            "/api/chatbot/chat",
            json={"message": "Delete me"},
            headers={"Authorization": f"Bearer {token}"},
        )
        conv_id = r.json()["conversation_id"]

        del_r = client.delete(
            f"/api/chatbot/conversations/{conv_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert del_r.status_code == 200

    def test_unauthenticated_chat_rejected(self):
        r = client.post("/api/chatbot/chat", json={"message": "Hello"})
        assert r.status_code == 401

    def test_chat_suggestions_endpoint(self):
        token = get_analyst_token()
        # General suggestions
        r = client.get("/api/chatbot/suggestions", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert "suggestions" in data
        assert len(data["suggestions"]) >= 5
        assert "Why was this incident flagged?" in data["suggestions"]

        # Incident-specific suggestions
        r2 = client.get("/api/chatbot/suggestions?incident_id=1", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200
        data2 = r2.json()
        assert len(data2["suggestions"]) >= 5

    def test_chat_with_incident_context(self):
        token = get_analyst_token()
        r = client.post(
            "/api/chatbot/chat",
            json={
                "message": "Why was this incident flagged?",
                "incident_id": 1,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["is_mock"] is True
        assert "SIMULATED MOCK AI" in data["content"]
        assert "Observed Telemetry" in data["content"]

    def test_chat_playbook_and_investigate_questions(self):
        token = get_analyst_token()
        # Playbook recommendation inquiry
        r = client.post(
            "/api/chatbot/chat",
            json={
                "message": "Which playbook is appropriate?",
                "incident_id": 1,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert "PLAYBOOK RECOMMENDATION" in r.json()["content"]
        assert "SIMULATION MODE" in r.json()["content"]

        # What to investigate next inquiry
        r2 = client.post(
            "/api/chatbot/chat",
            json={
                "message": "What should I investigate next?",
                "incident_id": 1,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200
        assert "INVESTIGATION ROADMAP" in r2.json()["content"]


# ============================================================
# MOCK ALERT GENERATOR TESTS
# ============================================================

class TestAlertGenerator:
    def test_generate_single_alert_analyst(self):
        token = get_analyst_token()
        r = client.post(
            "/api/alerts/generate/single",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "created"
        assert "incident" in data
        assert data["incident"]["is_simulated"] is True

    def test_generated_alert_has_simulated_tag(self):
        token = get_analyst_token()
        r = client.post(
            "/api/alerts/generate/single",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        inc = r.json()["incident"]
        # Verify title includes [SIMULATED]
        assert "[SIMULATED]" in inc["title"] or inc["is_simulated"] is True

    def test_generate_with_specific_category(self):
        token = get_analyst_token()
        r = client.post(
            "/api/alerts/generate/single",
            json={"category": "BRUTE_FORCE"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_invalid_category_rejected(self):
        token = get_analyst_token()
        r = client.post(
            "/api/alerts/generate/single",
            json={"category": "NONEXISTENT_CATEGORY"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400

    def test_batch_requires_admin(self):
        viewer_token = get_viewer_token()
        r = client.post(
            "/api/alerts/generate/batch",
            json={"count": 3},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    def test_batch_generation_admin(self):
        admin_token = get_admin_token()
        r = client.post(
            "/api/alerts/generate/batch",
            json={"count": 3},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 3

    def test_generated_alerts_persist_in_incidents(self):
        analyst_token = get_analyst_token()
        # Generate one
        client.post(
            "/api/alerts/generate/single",
            json={},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        # Check it appears in incidents list
        r = client.get(
            "/api/incidents",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 200
        # At least some incidents exist
        assert r.json()["total"] > 0

    def test_list_categories(self):
        token = get_analyst_token()
        r = client.get(
            "/api/alerts/generate/categories",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        cats = r.json()["categories"]
        assert len(cats) > 0
        keys = [c["key"] for c in cats]
        assert "BRUTE_FORCE" in keys

    def test_generator_status(self):
        token = get_analyst_token()
        r = client.get(
            "/api/alerts/generate/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert "scheduler_running" in r.json()


# ============================================================
# EMAIL NOTIFICATION TESTS
# ============================================================

class TestEmailNotifications:
    def test_get_email_config_admin(self):
        token = get_admin_token()
        r = client.get("/api/email/config", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert "email_enabled" in data
        assert "demo_mode" in data
        # Secrets not exposed
        assert "smtp_password" not in data
        assert "SMTP_PASSWORD" not in str(data)

    def test_email_config_requires_admin(self):
        viewer_token = get_viewer_token()
        r = client.get("/api/email/config", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 403

    def test_create_detection_rule(self):
        token = get_admin_token()
        unique_name = f"Test Rule — Failed Logins {uuid.uuid4().hex[:6]}"
        r = client.post(
            "/api/email/rules",
            json={
                "name": unique_name,
                "rule_type": "FAILED_LOGINS_BURST",
                "description": "Alert on repeated failures",
                "severity": "HIGH",
                "conditions": {"threshold": 10, "window_minutes": 5},
                "actions": ["SEND_EMAIL"],
                "enabled": True,
                "cooldown_minutes": 15,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == unique_name
        assert data["rule_type"] == "FAILED_LOGINS_BURST"
        assert data["id"] > 0

    def test_list_rules(self):
        token = get_admin_token()
        r = client.get("/api/email/rules", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_send_test_email_simulation(self):
        """In demo mode, test email must be simulated — not sent."""
        token = get_admin_token()
        r = client.post(
            "/api/email/test",
            json={"recipient": "test@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        # In demo mode, should be simulated
        assert data["status"] in ("SIMULATED", "DELIVERED", "FAILED", "QUEUED")
        # Status must not claim delivery if it's a simulation
        if data["is_simulation"]:
            assert data["status"] in ("SIMULATED",)

    def test_email_logs_viewable(self):
        token = get_analyst_token()
        r = client.get("/api/email/logs", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_invalid_rule_type_rejected(self):
        token = get_admin_token()
        r = client.post(
            "/api/email/rules",
            json={
                "name": "Bad Rule",
                "rule_type": "NONEXISTENT_TYPE",
                "cooldown_minutes": 15,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400

    def test_get_notification_recipients(self):
        token = get_analyst_token()
        r = client.get("/api/email/recipients", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert "recipients" in data
        assert isinstance(data["recipients"], list)
        assert len(data["recipients"]) > 0

    def test_update_notification_recipients_admin(self):
        token = get_admin_token()
        new_list = ["alert-soc@test.corp", "lead-analyst@test.corp"]
        r = client.post(
            "/api/email/recipients",
            json={"recipients": new_list},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "updated"
        assert "alert-soc@test.corp" in data["recipients"]

    def test_update_notification_recipients_requires_admin(self):
        token = get_analyst_token()
        r = client.post(
            "/api/email/recipients",
            json={"recipients": ["test@example.com"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_retry_email_delivery_admin(self):
        token = get_admin_token()
        test_res = client.post(
            "/api/email/test",
            json={"recipient": "retry.test@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert test_res.status_code == 200

        logs_res = client.get("/api/email/logs", headers={"Authorization": f"Bearer {token}"})
        logs = logs_res.json()
        assert len(logs) > 0
        target_log_id = logs[0]["id"]
        initial_retries = logs[0]["retry_count"]

        retry_res = client.post(
            f"/api/email/logs/{target_log_id}/retry",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert retry_res.status_code == 200
        retried_data = retry_res.json()
        assert retried_data["retry_count"] == initial_retries + 1

    def test_retry_email_requires_admin(self):
        analyst_token = get_analyst_token()
        r = client.post(
            "/api/email/logs/1/retry",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert r.status_code == 403

    def test_brute_force_correlation_triggers_incident_and_email(self):
        target_email = f"brute_victim_{uuid.uuid4().hex[:6]}@example.com"
        for _ in range(5):
            client.post("/api/auth/login", json={"email": target_email, "password": "WrongPassword!"})

        admin_token = get_admin_token()
        incidents_res = client.get(
            f"/api/incidents?search={target_email}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert incidents_res.status_code == 200
        data = incidents_res.json()
        assert data["total"] >= 1
        found = any("Brute-Force" in inc["title"] for inc in data["incidents"])
        assert found, f"Expected Brute-Force incident for {target_email}"

        logs_res = client.get("/api/email/logs", headers={"Authorization": f"Bearer {admin_token}"})
        logs = logs_res.json()
        assert any("Brute-Force" in l["subject"] for l in logs)

    def test_suspicious_login_after_failures_triggers_incident_and_email(self):
        unique_user_email = f"user_{uuid.uuid4().hex[:6]}@example.com"
        reg_res = client.post("/api/auth/register", json={
            "email": unique_user_email,
            "full_name": "Test Correlation User",
            "password": "ValidPassword123!",
        })
        assert reg_res.status_code == 201

        for _ in range(3):
            client.post("/api/auth/login", json={"email": unique_user_email, "password": "BadPassword123!"})

        login_res = client.post("/api/auth/login", json={"email": unique_user_email, "password": "ValidPassword123!"})
        assert login_res.status_code == 200

        admin_token = get_admin_token()
        incidents_res = client.get(
            f"/api/incidents?search={unique_user_email}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert incidents_res.status_code == 200
        data = incidents_res.json()
        found = any("Suspicious" in inc["title"] for inc in data["incidents"])
        assert found, f"Expected Suspicious Authentication incident for {unique_user_email}"

    def test_critical_incident_ingest_triggers_email_notification(self):
        admin_token = get_admin_token()
        unique_title = f"Critical Ingest Test {uuid.uuid4().hex[:6]}"
        inc_res = client.post(
            "/api/incidents",
            json={
                "title": unique_title,
                "description": "Immediate escalation required for critical root exploit.",
                "severity": "CRITICAL",
                "category": "Privilege Escalation",
                "source": "EDR Sensor",
                "source_ip": "10.0.0.99",
                "target_system": "CORE-SRV-01",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert inc_res.status_code == 201

        logs_res = client.get("/api/email/logs", headers={"Authorization": f"Bearer {admin_token}"})
        logs = logs_res.json()
        found_email = any(unique_title in l["subject"] or "Critical" in l["subject"] for l in logs)
        assert found_email, "Expected email dispatch recorded for CRITICAL incident"



# ============================================================
# PHASE 3: DEFENSIVE PLAYBOOKS TESTS
# ============================================================

class TestDefensivePlaybooks:
    def test_playbook_catalog_has_15_entries(self):
        """All 15 realistic defensive playbooks must be seeded and available."""
        token = get_analyst_token()
        r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 15, f"Expected >= 15 playbooks, got {len(data)}"

    def test_playbook_structured_metadata_present(self):
        """Each playbook must include risk_level, operational_impact, required_permissions, preconditions, incident_types."""
        token = get_analyst_token()
        r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        for pb in r.json():
            assert "risk_level" in pb, f"Playbook '{pb['name']}' missing risk_level"
            assert "operational_impact" in pb, f"Playbook '{pb['name']}' missing operational_impact"
            assert "required_permissions" in pb, f"Playbook '{pb['name']}' missing required_permissions"
            assert "preconditions" in pb, f"Playbook '{pb['name']}' missing preconditions"
            assert "incident_types" in pb, f"Playbook '{pb['name']}' missing incident_types"
            assert isinstance(pb["required_permissions"], list)
            assert isinstance(pb["preconditions"], list)
            assert isinstance(pb["incident_types"], list)

    def test_playbook_steps_have_action_type(self):
        """All steps in each playbook should have action_type field."""
        token = get_analyst_token()
        r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        for pb in r.json():
            for step in pb.get("steps", []):
                assert "action_type" in step, f"Step '{step.get('desc')}' in '{pb['name']}' missing action_type"

    def test_playbook_recommendation_endpoint_returns_ranked_list(self):
        """GET /incidents/{id}/playbook/recommend must return ordered recommendation list."""
        token = get_analyst_token()
        r = client.get("/api/incidents/1/playbook/recommend", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert "incident_id" in data
        assert "recommendations" in data
        assert data["total_playbooks"] >= 15
        recs = data["recommendations"]
        assert len(recs) >= 1
        # First recommendation must be primary
        assert recs[0]["is_primary"] is True
        # Scores must be in descending order
        for i in range(len(recs) - 1):
            assert recs[i]["score"] >= recs[i + 1]["score"], "Recommendations must be sorted descending by score"

    def test_playbook_recommendation_includes_metadata(self):
        """Each recommendation must contain match_reason, risk_level, step_count."""
        token = get_analyst_token()
        r = client.get("/api/incidents/1/playbook/recommend", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        for rec in r.json()["recommendations"]:
            assert "match_reason" in rec and rec["match_reason"]
            assert "risk_level" in rec
            assert "operational_impact" in rec
            assert "step_count" in rec
            assert rec["step_count"] > 0

    def test_playbook_execute_with_specific_playbook_id(self):
        """Executing a specific playbook by ID should complete successfully with steps."""
        token = get_analyst_token()
        # Get list and pick the first playbook
        list_r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        assert list_r.status_code == 200
        first_pb = list_r.json()[0]
        pb_id = first_pb["id"]
        expected_steps = len(first_pb["steps"])  # use actual steps list length

        exec_r = client.post(
            "/api/incidents/1/playbook/execute",
            json={"execution_mode": "SIMULATION", "playbook_id": pb_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert exec_r.status_code == 200
        data = exec_r.json()
        assert data["status"] == "COMPLETED"
        assert data["execution_mode"] == "SIMULATION"
        assert len(data["steps_results"]) == expected_steps
        # Verify action_type is present in each step result
        for step in data["steps_results"]:
            assert "action_type" in step

    def test_playbook_ransomware_exists_with_correct_category(self):
        """Ransomware Host Containment playbook must be in Endpoint / Malware category."""
        token = get_analyst_token()
        r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        ransomware_pbs = [p for p in r.json() if "Ransomware" in p["name"]]
        assert len(ransomware_pbs) >= 1
        assert ransomware_pbs[0]["severity"] == "CRITICAL"
        assert "Ransomware" in ransomware_pbs[0]["incident_types"]

    def test_playbook_get_by_id(self):
        """GET /playbooks/{id} must return the playbook with all structured fields."""
        token = get_analyst_token()
        list_r = client.get("/api/playbooks", headers={"Authorization": f"Bearer {token}"})
        pb_id = list_r.json()[0]["id"]
        r = client.get(f"/api/playbooks/{pb_id}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == pb_id
        assert "steps" in data and len(data["steps"]) > 0
        assert "risk_level" in data



# ============================================================
# PHASE 4: AUTO-ALERT SCHEDULER TESTS
# ============================================================

class TestAutoAlertScheduler:
    """Phase 4 - verify the scheduler pause / resume / configure API."""

    def test_scheduler_status_is_accessible_by_analyst(self):
        """Any authenticated user can GET the scheduler status."""
        token = get_analyst_token()
        r = client.get(
            "/api/alerts/generate/scheduler/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "running" in data
        assert "interval_seconds" in data
        assert "total_generated" in data
        assert "paused" in data

    def test_scheduler_status_has_expected_fields(self):
        """Status payload must include paused flag, interval, recipients."""
        token = get_analyst_token()
        r = client.get(
            "/api/alerts/generate/scheduler/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = r.json()
        assert isinstance(data["interval_seconds"], int)
        assert isinstance(data["paused"], bool)
        assert isinstance(data["total_generated"], int)
        assert "recipients" in data

    def test_scheduler_pause_requires_admin(self):
        """Non-admin users must NOT be able to pause the scheduler."""
        token = get_viewer_token()
        r = client.post(
            "/api/alerts/generate/scheduler/pause",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_scheduler_resume_requires_admin(self):
        """Non-admin users must NOT be able to resume the scheduler."""
        token = get_viewer_token()
        r = client.post(
            "/api/alerts/generate/scheduler/resume",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_scheduler_config_requires_admin(self):
        """Non-admin users must NOT be able to change the interval."""
        token = get_viewer_token()
        r = client.patch(
            "/api/alerts/generate/scheduler/config",
            json={"interval_seconds": 120},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_scheduler_config_interval_update(self):
        """Admin can update the interval; response reflects the new value."""
        token = get_admin_token()
        r = client.patch(
            "/api/alerts/generate/scheduler/config",
            json={"interval_seconds": 90},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "updated"
        assert data["interval_seconds"] == 90

    def test_scheduler_config_rejects_too_small_interval(self):
        """Interval below 10 s must be rejected with 422."""
        token = get_admin_token()
        r = client.patch(
            "/api/alerts/generate/scheduler/config",
            json={"interval_seconds": 5},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_scheduler_config_rejects_too_large_interval(self):
        """Interval above 3600 s must be rejected with 422."""
        token = get_admin_token()
        r = client.patch(
            "/api/alerts/generate/scheduler/config",
            json={"interval_seconds": 9999},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_scheduler_pause_and_resume_cycle(self):
        """Admin can pause the scheduler and resume it; paused flag toggles."""
        token = get_admin_token()

        # Scheduler starts automatically via app lifespan.
        # Pause
        r_pause = client.post(
            "/api/alerts/generate/scheduler/pause",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r_pause.status_code == 200
        assert r_pause.json()["status"] == "paused"
        assert r_pause.json()["paused"] is True

        # Resume
        r_resume = client.post(
            "/api/alerts/generate/scheduler/resume",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r_resume.status_code == 200
        assert r_resume.json()["status"] == "resumed"
        assert r_resume.json()["paused"] is False

    def test_scheduler_interval_restored_to_default(self):
        """Restore interval to 50 s so subsequent runs are not affected."""
        token = get_admin_token()
        r = client.patch(
            "/api/alerts/generate/scheduler/config",
            json={"interval_seconds": 50},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["interval_seconds"] == 50
