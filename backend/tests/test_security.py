"""
Security & Hardening Test Suite
"""
import pytest


def test_unauthenticated_request_rejected(client):
    """Test accessing protected endpoints without JWT returns 401 Unauthorized."""
    res = client.get("/api/incidents")
    assert res.status_code == 401


def test_tampered_jwt_rejected(client):
    """Test accessing protected endpoints with tampered JWT returns 401."""
    res = client.get("/api/incidents", headers={"Authorization": "Bearer invalid.fake.token"})
    assert res.status_code == 401


def test_sql_injection_payload_in_search(client, auth_headers_analyst):
    """Test SQL injection strings in search query do not compromise or crash database."""
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE incidents; --",
        "1 UNION SELECT 1,2,3,4--",
        "admin'--",
    ]
    for payload in sqli_payloads:
        res = client.get(f"/api/incidents?search={payload}", headers=auth_headers_analyst)
        assert res.status_code == 200  # Safely parameterized query returning filtered or empty list
        assert isinstance(res.json()["incidents"], list)


def test_security_headers_present(client):
    """Test security response headers are present on all responses."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("x-xss-protection") == "1; mode=block"


def test_ssrf_protection_validator():
    """Test SSRF validation utility blocks loopback, private, and cloud metadata destinations."""
    from app.core.ssrf_protection import validate_safe_outbound_url

    # Restricted loopback
    safe, msg = validate_safe_outbound_url("http://127.0.0.1:8000/api")
    assert not safe
    assert "loopback" in msg.lower() or "prohibited" in msg.lower()

    # Restricted cloud metadata
    safe, msg = validate_safe_outbound_url("http://169.254.169.254/latest/meta-data/")
    assert not safe

    # Restricted hostname
    safe, msg = validate_safe_outbound_url("http://localhost:3000")
    assert not safe

    # Invalid scheme
    safe, msg = validate_safe_outbound_url("ftp://example.com/file")
    assert not safe
    assert "scheme" in msg.lower()


def test_ssrf_blocked_on_integration_update(client, auth_headers_admin):
    """Test attempting to configure a private IP endpoint on an integration is rejected with 400."""
    res = client.patch("/api/integrations/1", headers=auth_headers_admin, json={
        "endpoint_url": "http://127.0.0.1:8000/secret",
    })
    assert res.status_code == 400
    assert "ssrf" in res.json()["detail"].lower()

