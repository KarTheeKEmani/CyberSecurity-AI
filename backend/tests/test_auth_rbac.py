"""
Auth & RBAC Test Suite
"""
import pytest


def test_login_success(client):
    """Test valid login returns signed JWT access token and user profile."""
    res = client.post("/api/auth/login", json={
        "email": "sarah.chen@cybersentinel.ai",
        "password": "Password123!",
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "sarah.chen@cybersentinel.ai"
    assert data["user"]["role"] == "ANALYST"


def test_login_invalid_password(client):
    """Test invalid password rejects login with 401."""
    res = client.post("/api/auth/login", json={
        "email": "sarah.chen@cybersentinel.ai",
        "password": "WrongPassword999!",
    })
    assert res.status_code == 401
    assert "detail" in res.json()


def test_get_me(client, auth_headers_analyst):
    """Test retrieving current authenticated user profile."""
    res = client.get("/api/auth/me", headers=auth_headers_analyst)
    assert res.status_code == 200
    assert res.json()["email"] == "sarah.chen@cybersentinel.ai"


def test_rbac_admin_allowed_user_creation(client, auth_headers_admin):
    """Test Admin can create new platform users."""
    res = client.post("/api/users", headers=auth_headers_admin, json={
        "email": "new.analyst@cybersentinel.ai",
        "full_name": "New Analyst",
        "password": "SecurePassword123!",
        "role": "ANALYST",
    })
    assert res.status_code == 201
    assert res.json()["email"] == "new.analyst@cybersentinel.ai"


def test_rbac_viewer_forbidden_incident_creation(client, auth_headers_viewer):
    """Test Viewer is blocked from creating incidents (403 Forbidden)."""
    res = client.post("/api/incidents", headers=auth_headers_viewer, json={
        "title": "Viewer Attempted Incident",
        "severity": "HIGH",
    })
    assert res.status_code == 403


def test_rbac_viewer_forbidden_playbook_execution(client, auth_headers_viewer):
    """Test Viewer is blocked from executing containment playbooks."""
    res = client.post("/api/incidents/1/playbook/execute", headers=auth_headers_viewer, json={
        "execution_mode": "SIMULATION"
    })
    assert res.status_code == 403


def test_public_registration_default_role(client):
    """Test public registration assigns ANALYST role by default and succeeds."""
    res = client.post("/api/auth/register", json={
        "email": "fresh.recruit@cybersentinel.ai",
        "full_name": "Fresh Recruit",
        "password": "StrongPassword123!",
        "role": "ANALYST",
    })
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == "fresh.recruit@cybersentinel.ai"
    assert data["role"] == "ANALYST"


def test_public_registration_admin_forbidden(client):
    """Test public registration attempting to self-assign ADMIN is strictly rejected with 403."""
    res = client.post("/api/auth/register", json={
        "email": "hacker@cybersentinel.ai",
        "full_name": "Rogue Admin",
        "password": "Password123!",
        "role": "ADMIN",
    })
    assert res.status_code == 403
    assert "administrator" in res.json()["detail"].lower()


def test_public_registration_validation(client):
    """Test public registration rejects invalid email or short password."""
    # Invalid email (422 Unprocessable Entity)
    res1 = client.post("/api/auth/register", json={
        "email": "notanemail",
        "full_name": "Test User",
        "password": "ValidPassword123!",
    })
    assert res1.status_code == 422

    # Short password < 8 chars (422 Unprocessable Entity)
    res2 = client.post("/api/auth/register", json={
        "email": "valid@cybersentinel.ai",
        "full_name": "Test User",
        "password": "short",
    })
    assert res2.status_code == 422


def test_logout_endpoint(client, auth_headers_analyst):
    """Test logout endpoint records audit log and returns success message."""
    res = client.post("/api/auth/logout", headers=auth_headers_analyst)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

