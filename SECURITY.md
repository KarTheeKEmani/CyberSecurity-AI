# Security Architecture & RBAC Policy — AIAC Cyber

## 1. Authentication & Session Security

- **Password Hashing**: Passwords are encrypted using modern `bcrypt` key derivation with automated per-user salt generation.
- **Signed JWT Tokens**: Stateless, cryptographically signed JSON Web Tokens (HMAC-SHA256).
  - Short-lived Access Tokens (24 hours).
  - Extended Refresh Tokens (7 days).
- **Token Verification**: Every protected REST and WebSocket endpoint verifies the token signature and checks that the user's account is currently active.

---

## 2. Role-Based Access Control (RBAC) Matrix

| Resource / Action | VIEWER (Auditor) | ANALYST (Responder) | ADMIN (Security Admin) |
|---|:---:|:---:|:---:|
| **View Dashboard & Metrics** | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **View Incident Telemetry** | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Ingest New Incident** | ❌ Forbidden | ✅ Allowed | ✅ Allowed |
| **Update Incident Status** | ❌ Forbidden | ✅ Allowed | ✅ Allowed |
| **Trigger AI Triage** | ❌ Forbidden | ✅ Allowed | ✅ Allowed |
| **Simulate Containment Playbook** | ❌ Forbidden | ✅ Allowed | ✅ Allowed |
| **Delete Incident** | ❌ Forbidden | ❌ Forbidden | ✅ Allowed |
| **Manage Users & Roles** | ❌ Forbidden | ❌ Forbidden | ✅ Allowed |
| **Create / Revoke API Keys** | ❌ Forbidden | ❌ Forbidden | ✅ Allowed |
| **Test Integrations** | ❌ Forbidden | ✅ Allowed | ✅ Allowed |
| **View Tamper-Evident Audit Logs** | ❌ Forbidden | ❌ Forbidden | ✅ Allowed |

Server-side enforcement is strictly executed via the `require_role(["ADMIN", "ANALYST"])` FastAPI dependency.

---

## 3. Cryptographic API Key Security

- Plaintext API keys (`cs_live_...`) are generated using the cryptographically strong `secrets.token_urlsafe` module.
- The raw key is revealed **ONCE** to the administrator upon creation and is **NEVER** stored in the database.
- Only the SHA-256 hash (`hashlib.sha256(raw_key.encode('utf-8')).hexdigest()`) is stored for verification.

---

## 4. Tamper-Evident Audit Logging

Every security-sensitive operation is persisted to the `audit_logs` table:
- User login / failed login attempts
- Incident creation, modification, deletion, and status transitions
- AI triage executions
- Playbook simulation runs
- API key generation and revocation
- User creation and role modifications

**Privacy & Safety Guardrails**: Passwords, JWT secrets, raw API keys, and sensitive tokens are strictly excluded from audit logs.

---

## 5. Defensive Hardening & Headers

All HTTP responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- SQLAlchemy parameterized queries preventing SQL Injection.
