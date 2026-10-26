# Testing & Verification Guide — AIAC Cyber

## 1. Test Suite Architecture

The test suite is built using **pytest** and **FastAPI TestClient** with isolated in-memory SQLite instances using `StaticPool` for high-speed deterministic verification.

Directory: `backend/tests/`

| Test Module | Coverage Area |
|---|---|
| `test_auth_rbac.py` | JWT login, invalid passwords, token refresh, `/api/auth/me`, Admin vs Viewer permissions |
| `test_incidents_lifecycle.py` | CRUD operations, strict status transitions, keyword search, severity filtering |
| `test_ai_playbooks_analytics.py`| AI triage reasoning, playbook simulations, database analytics, audit logs, API key lifecycles |
| `test_security.py` | Unauthenticated rejection, tampered tokens, SQL injection defense, security headers |
| `test_live_workflow.py` | Multi-step end-to-end incident lifecycle from creation to resolution and audit verification |

---

## 2. Executing Automated Tests

```bash
cd backend
source venv/bin/activate
pytest -v
```

### Expected Output
```
======================== 22 passed, 1 warning in ~25s ========================
```
