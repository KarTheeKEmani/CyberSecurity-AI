# REST API Documentation — AIAC Cyber

Base URL: `http://localhost:8000/api`  
Interactive OpenAPI / Swagger UI: `http://localhost:8000/docs`

---

## 1. Authentication Endpoints

### `POST /api/auth/login`
Authenticate user with email and password.
- **Request Body**:
  ```json
  {
    "email": "sarah.chen@cybersentinel.ai",
    "password": "Password123!",
    "role": "analyst"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "user": {
      "id": 2,
      "email": "sarah.chen@cybersentinel.ai",
      "full_name": "Sarah Chen",
      "role": "ANALYST",
      "is_active": true,
      "mfa_enabled": true,
      "created_at": "2026-08-01T07:00:00Z"
    }
  }
  ```

### `GET /api/auth/me`
Retrieve profile of currently authenticated user.
- **Headers**: `Authorization: Bearer <token>`
- **Response (200 OK)**: `UserResponse` object.

### `POST /api/auth/refresh`
Obtain a new access token using a valid refresh token.
- **Request Body**: `{"refresh_token": "..."}`

### `POST /api/auth/logout`
Sign out and record audit event.

---

## 2. Incident Endpoints

### `GET /api/incidents`
List incidents with filtering and pagination.
- **Query Parameters**:
  - `page` (int, default: 1)
  - `page_size` (int, default: 50)
  - `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - `status` (`DETECTED`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`)
  - `search` (string)
  - `category` (string)
  - `assignee` (string)
- **Response (200 OK)**:
  ```json
  {
    "total": 14,
    "page": 1,
    "page_size": 50,
    "incidents": [...]
  }
  ```

### `POST /api/incidents`
Create and ingest a new security incident. Requires `ADMIN` or `ANALYST` role.
- **Request Body**:
  ```json
  {
    "title": "Cobalt Strike Beaconing on Core Router",
    "description": "Observed outbound HTTPS beaconing pattern.",
    "severity": "CRITICAL",
    "category": "C2 Beacon",
    "source": "EDR (CrowdStrike)",
    "source_ip": "198.51.100.24",
    "target_system": "CORE-RTR-01",
    "assignee": "Sarah Chen"
  }
  ```
- **Response (201 Created)**: `IncidentResponse` object with generated `public_id` (e.g. `INC-2024-8847`).

### `GET /api/incidents/{id}`
Retrieve full incident telemetry including IOCs, MITRE ATT&CK techniques, AI analyses, and playbook execution history.

### `PATCH /api/incidents/{id}/status`
Update incident lifecycle status with strict transition validation.
- **Request Body**:
  ```json
  {
    "status": "CONTAINED"
  }
  ```

---

## 3. AI Triage Endpoints

### `POST /api/incidents/{id}/triage`
Execute AI-assisted triage analysis on the incident.
- **Request Body**: `{}` (optional `provider`, `model`)
- **Response (200 OK)**:
  ```json
  {
    "classification": "CONFIRMED_THREAT",
    "severity_score": 9.8,
    "confidence": 98.5,
    "threat_type": "Ransomware Execution — LockBit 3.0",
    "attack_stage": "Impact & Defense Evasion",
    "root_cause": "The endpoint was compromised via malicious macro...",
    "summary": "High-impact LockBit 3.0 ransomware infection...",
    "iocs": ["185.220.101.45", "powershell.exe -enc ..."],
    "mitre_techniques": [
      {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"}
    ],
    "recommendations": ["Isolate host", "Terminate process tree"],
    "recommended_playbook": {
      "name": "Ransomware Host Containment & Recovery",
      "steps": [...]
    },
    "provider": "mock",
    "model": "aiac-cyber-triage-v2.5 (Simulated Engine)",
    "created_at": "2026-08-31T07:30:00Z"
  }
  ```

---

## 4. Playbook Endpoints

### `GET /api/playbooks`
Retrieve list of available automated containment playbooks.

### `POST /api/incidents/{id}/playbook/execute`
Execute defensive containment playbook in SIMULATION MODE.
- **Request Body**:
  ```json
  {
    "execution_mode": "SIMULATION"
  }
  ```

---

## 5. Analytics Endpoints

### `GET /api/analytics/summary`
Retrieve high-level summary KPIs (Active incidents, critical count, MTTR, accuracy).

### `GET /api/analytics/overview`
Retrieve 30-day trends, attack vectors, severity breakdown, and system vulnerability heatmap matrix.

---

## 6. Audit & Admin Endpoints

### `GET /api/audit`
Retrieve search-filtered audit trail logs.

### `GET /api/api-keys`
List stored API keys with masked prefixes and request metrics.

### `POST /api/api-keys`
Generate a new scoped API key. Returns raw key once.

---

## 7. AI Threat Assistant (Chatbot) Endpoints

### `POST /api/chatbot/chat`
Send query to AI Threat Assistant with optional conversation and incident telemetry context.
- **Request Body**:
  ```json
  {
    "message": "Analyze beaconing interval patterns for this incident",
    "conversation_id": 1,
    "incident_id": 3
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "conversation_id": 1,
    "response": "Based on incident telemetry INC-2024-8847...",
    "is_mock": true,
    "model": "cyber-sentinel-threat-assist-v1"
  }
  ```

### `GET /api/chatbot/conversations`
List user's active threat investigation threads.
- **Response (200 OK)**: Array of `ConversationResponse` objects.

### `GET /api/chatbot/conversations/{id}/messages`
Retrieve chronological message history for a conversation.
- **Response (200 OK)**: Array of `MessageResponse` objects (`id`, `role`, `content`, `is_mock`, `created_at`).

### `DELETE /api/chatbot/conversations/{id}`
Delete a conversation thread and its associated message history.

---

## 8. Mock Alert Generator Endpoints

### `POST /api/alerts/generate/single`
Synthesize and ingest a realistic multi-vector security incident. Broadcasts `incident.created` via authenticated WebSocket.
- **Request Body**:
  ```json
  {
    "category": "BRUTE_FORCE",
    "severity": "HIGH"
  }
  ```
- **Response (201 Created)**: Created `IncidentResponse` with `[SIMULATED]` indicator tag.

### `POST /api/alerts/generate/batch`
Burst injection of multiple synthetic telemetry events (1 to 20 incidents).
- **Request Body**:
  ```json
  {
    "count": 5,
    "category": null,
    "severity": null
  }
  ```
- **Response (201 Created)**: `{ "message": "Successfully generated 5 mock incidents", "count": 5, "incidents": [...] }`.

### `GET /api/alerts/generate/categories`
Retrieve catalog of available attack scenario templates (e.g. Cobalt Strike, Ransomware, SQLi, Exfiltration).

### `GET /api/alerts/generate/status`
Retrieve simulation engine status and total generated incident metrics.

---

## 9. Email Notifications & Detection Rules Endpoints

### `GET /api/email/config`
Retrieve SMTP dispatch configuration status. Secrets like passwords are never exposed. Requires `ADMIN` role.
- **Response (200 OK)**:
  ```json
  {
    "email_enabled": false,
    "demo_mode": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "configured",
    "sender_email": "alerts@cybersentinel.ai"
  }
  ```

### `GET /api/email/rules`
List all configured automated alert and detection trigger rules.

### `POST /api/email/rules`
Create a new automated detection rule. Requires `ADMIN` role.
- **Request Body**:
  ```json
  {
    "name": "Ransomware Burst Detection",
    "rule_type": "RANSOMWARE_DETECTED",
    "description": "Alert SOC on-call engineers when ransomware behavior is detected",
    "severity": "CRITICAL",
    "cooldown_minutes": 15,
    "actions": ["SEND_EMAIL"],
    "enabled": true
  }
  ```

### `PATCH /api/email/rules/{id}`
Update rule parameters or toggle active state (`enabled: true/false`).

### `DELETE /api/email/rules/{id}`
Delete a detection rule.

### `GET /api/email/logs`
Retrieve paginated audit logs of notification dispatches.
- **Query Parameters**: `page` (int, default: 1)
- **Response (200 OK)**: `{ "logs": [...], "total": 12, "page": 1, "pages": 1 }`.

### `POST /api/email/test`
Dispatch a test security notification. In demo mode (`EMAIL_DEMO_MODE=true`), writes simulated dispatch log without connecting to external SMTP.
- **Request Body**: `{"recipient": "soc-lead@corp.net"}`

