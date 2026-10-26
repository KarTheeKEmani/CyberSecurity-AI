# Real-Time WebSocket Infrastructure — AIAC Cyber

## 1. WebSocket Endpoint & Connection Protocol

- **Endpoint**: `/api/ws`
- **URL**: `ws://localhost:8000/api/ws?token=<JWT_ACCESS_TOKEN>`
- **Connection Management**: Centralized singleton `ConnectionManager` handling client registration, heartbeat pings/pongs, and broadcast queues.

---

## 2. Event Format Contract

All real-time messages adhere to a standardized JSON schema:

```json
{
  "type": "incident.created",
  "timestamp": "2026-08-31T07:30:00Z",
  "data": {
    "id": 14,
    "public_id": "INC-2024-8847",
    "title": "Ransomware Execution Detected",
    "severity": "CRITICAL",
    "status": "DETECTED",
    "source": "EDR (CrowdStrike)",
    "assignee": "Sarah Chen",
    "created_at": "2026-08-31T07:30:00Z"
  }
}
```

---

## 3. Supported Real-Time Event Types

| Event Type | Trigger | Payload Summary |
|---|---|---|
| `incident.created` | New incident ingested | Incident ID, public ID, severity, title, assignee |
| `incident.updated` | Incident metadata edited | Incident ID, updated fields, timestamp |
| `incident.status_changed` | Lifecycle status transition | Incident ID, old_status, new_status |
| `incident.deleted` | Admin deletes incident | Incident ID, public_id |
| `ai.analysis.started` | AI triage initiated | Incident ID, provider name |
| `ai.analysis.completed` | AI triage finished | Incident ID, classification, RCA, playbook |
| `ai.analysis.failed` | AI triage error | Incident ID, error message |
| `playbook.started` | Playbook simulation initiated | Incident ID, execution ID, step count |
| `playbook.completed` | Playbook simulation finished | Execution ID, new incident status (`CONTAINED`) |
| `audit.created` | New audit log recorded | Public audit ID, action, user |
| `notification.created` | Alert dispatched | Alert title, severity color |
| `integration.status_changed`| Integration connection tested | Integration ID, name, new status |

---

## 4. Two-Browser Synchronization Demonstration

1. Open **Browser A** (Analyst View): Log in as `sarah.chen@cybersentinel.ai`. Observe the incident queue and dashboard counters.
2. Open **Browser B** (Admin View): Log in as `admin@cybersentinel.ai`. Click **New Incident** and submit a new alert (`INC-2024-9001 - Unauthorized AWS S3 Bucket Exfiltration`).
3. **Browser A** receives the `incident.created` WebSocket event and automatically updates the active incident list and badge counters **WITHOUT refreshing the page**.
4. In **Browser A**, open the incident drawer and click **Run AI Triage**.
5. Once complete, trigger **Simulate Containment**.
6. **Browser B** automatically receives the `incident.status_changed` (`CONTAINED`) and `playbook.completed` events, updating its live queue instantly.
