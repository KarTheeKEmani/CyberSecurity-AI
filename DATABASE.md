# Database Specification — AIAC Cyber

## 1. Relational Schema Architecture (PostgreSQL)

AIAC Cyber uses SQLAlchemy 2.0 ORM models with strictly defined foreign key constraints, indexes, and cascading deletion policies.

```mermaid
erDiagram
    USERS ||--o{ API_KEYS : owns
    USERS ||--o{ AUDIT_LOGS : records
    INCIDENTS ||--o{ IOCS : contains
    INCIDENTS ||--o{ MITRE_TECHNIQUES : maps
    INCIDENTS ||--o{ AI_ANALYSES : triages
    INCIDENTS ||--o{ PLAYBOOK_EXECUTIONS : executes
    INCIDENTS ||--o{ NOTIFICATIONS : triggers
    PLAYBOOKS ||--o{ PLAYBOOK_EXECUTIONS : defines

    USERS {
        int id PK
        string email UK
        string full_name
        string password_hash
        string role
        boolean is_active
        boolean mfa_enabled
        datetime last_login
        datetime created_at
    }

    INCIDENTS {
        int id PK
        string public_id UK
        string title
        text description
        string severity
        string status
        string category
        string source
        string source_ip
        string target_system
        string assignee
        float risk_score
        json raw_logs
        datetime created_at
        datetime resolved_at
    }

    IOCS {
        int id PK
        int incident_id FK
        string type
        string value
        float confidence
        datetime created_at
    }

    MITRE_TECHNIQUES {
        int id PK
        int incident_id FK
        string technique_id
        string technique_name
        string tactic
    }

    AI_ANALYSES {
        int id PK
        int incident_id FK
        string provider
        string model
        string classification
        float severity_score
        float confidence
        string threat_type
        text root_cause
        json recommendations
        datetime created_at
    }

    PLAYBOOKS {
        int id PK
        string name UK
        string category
        string severity
        json steps
        boolean enabled
    }

    PLAYBOOK_EXECUTIONS {
        int id PK
        int incident_id FK
        int playbook_id FK
        string requested_by
        string status
        string execution_mode
        json steps_results
        datetime started_at
        datetime completed_at
    }

    AUDIT_LOGS {
        int id PK
        string public_id UK
        int user_id FK
        string user_email
        string action
        string resource
        string resource_id
        text detail
        string severity
        string ip_address
        datetime timestamp
    }
```

---

## 2. Alembic Migrations

Schema migrations are managed via Alembic:
- Configuration: `backend/alembic.ini`
- Environment: `backend/alembic/env.py`
- Version scripts: `backend/alembic/versions/`

### Applying Migrations
```bash
cd backend
alembic upgrade head
```

---

## 3. Database Seeder
The seed service (`backend/app/db/seed.py`) executes during startup when `DEMO_MODE=True`, populating realistic SOC telemetry, users, playbooks, integrations, API keys, and audit logs.
