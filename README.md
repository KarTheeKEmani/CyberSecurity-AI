# AIAC Cyber — AI-Assisted Cybersecurity Incident Response Platform

![AIAC Cyber Platform Banner](https://img.shields.io/badge/AIAC%20Cyber-v2.5.0-blue?style=for-the-badge&logo=shield)
![Python FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=for-the-badge&logo=postgresql)
![WebSockets](https://img.shields.io/badge/WebSockets-Real--Time-00D4FF?style=for-the-badge)
![Docker Ready](https://img.shields.io/badge/Docker-Multi--Container-2496ED?style=for-the-badge&logo=docker)

AIAC Cyber is an enterprise-grade, full-stack cybersecurity incident response platform designed for Security Operations Centers (SOC). It provides real-time telemetry streaming, intelligent AI triage reasoning, responsible containment playbook simulations with human-in-the-loop oversight, tamper-evident audit trails, and role-based access control.

---

## 🏛 System Architecture Overview

```
                          AIAC CYBER SOC PLATFORM
                                     │
                 ┌───────────────────┴───────────────────┐
                 │                                       │
           FRONTEND UI                             BACKEND API
     Vanilla HTML5 / ES6 / CSS                   Python 3.10+ FastAPI
     (Liquid Glass Design System)               (SQLAlchemy 2.x / Alembic)
                 │                                       │
                 │ ─── REST (JWT Bearer Auth) ─────────► │
                 │                                       ├── PostgreSQL Database
                 │ ◄── Real-Time WebSockets (/api/ws) ── │── AI Reasoning Engine
                 │                                       └── Playbook Simulation Runner
                 ▼                                       
        LIVE SOC DASHBOARD
   (Zero-Refresh UI Updates)
```

---

## 🚀 Quick Start & Local Setup

### Prerequisites
- **Python 3.10+** (Tested on Python 3.11, 3.12, 3.15)
- **Node/Nginx/Python** (For serving static frontend files)
- **Docker & Docker Compose** (Optional, for full containerized stack)

---

### Method 1: Local Development (FastAPI + SQLite/Postgres)

#### 1. Setup Backend
```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **API Server**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`
- **Health Check**: `http://localhost:8000/health`

#### 2. Launch Frontend
In a new terminal window at the project root:
```bash
# Serve static frontend on port 3000
python3 -m http.server 3000

# Open in your browser:
# http://localhost:3000/index.html
```

---

### Method 2: Docker Compose (Full-Stack Multi-Container)

To spin up the complete isolated system with PostgreSQL, FastAPI, and Nginx frontend:
```bash
docker compose up --build
```
- **Frontend SOC**: `http://localhost:3000`
- **Backend API**: `http://localhost:8000`
- **PostgreSQL**: `localhost:5432`

---

## 🔐 Default Demo Accounts (RBAC)

All accounts are pre-seeded in the database:

| Role | Email | Password | Permissions & Capabilities |
|------|-------|----------|----------------------------|
| **Lead Analyst** | `sarah.chen@cybersentinel.ai` | `Password123!` | Ingest incidents, trigger AI triage, simulate playbooks, investigate alerts |
| **Security Admin** | `admin@cybersentinel.ai` | `Password123!` | Manage users, generate/revoke API keys, configure integrations, view full audit logs |
| **Auditor / Viewer** | `viewer@cybersentinel.ai` | `Password123!` | Read-only access to dashboard, incident queues, and analytics |

---

## 🛡 Key Features

1. **Real-Time SOC Command Center**
   - Live telemetry feed connected via authenticated WebSockets (`/api/ws`).
   - Dynamic UI updates without page refreshes when incidents are created, triaged, or updated across browsers.
   - Status badge indicators (● LIVE, ○ RECONNECTING, ○ OFFLINE).

2. **Responsible AI Triage Engine**
   - Structured threat reasoning (Threat Type, Severity Score, Confidence %, Root Cause Analysis).
   - Automated extraction of Indicators of Compromise (IOCs: IPs, URLs, Hashes, Domains).
   - MITRE ATT&CK technique mapping (e.g. `T1059.001 PowerShell`, `T1486 Data Encrypted for Impact`).
   - Clearly badged as `SIMULATED AI` / `RESPONSIBLE AI` with human approval required.

3. **Playbook Containment Simulations**
   - Simulated defensive countermeasures (network isolation, process hierarchy termination, IP border blocking, immutable backup restoration).
   - Strict `SIMULATION MODE` labeling to prevent unauthorized host changes.
   - Automatic incident lifecycle progression (`DETECTED` → `TRIAGED` → `INVESTIGATING` → `CONTAINED` → `RESOLVED`).

4. **Threat Analytics & Vulnerability Heatmap**
   - Database-aggregated 30-day incident trends.
   - Attack vector breakdown (Phishing, Exploitation, Credential Theft, Malware).
   - Infrastructure exposure matrix (Systems vs Threat Classifications).
   - Mean Time to Resolution (MTTR) calculation.

5. **Security & Administration**
   - Role-Based Access Control (`ADMIN`, `ANALYST`, `VIEWER`).
   - Tamper-evident, immutable audit trail for all operational actions.
   - SHA-256 hashed API key management with single-reveal key creation.
   - Comprehensive security headers (`nosniff`, `DENY`, `XSS protection`).

6. **AI Threat Assistant (Co-Pilot Chatbot)**
   - Interactive LLM-powered SOC co-pilot for investigative assistance and forensic guidance.
   - Live incident telemetry context binding, thread history persistence, query sanitization, and rate limiting.
   - Distinct `[SIMULATED]` vs real LLM provider labeling.

7. **Mock Alert Generator & Simulator**
   - 9 high-fidelity MITRE ATT&CK attack scenario templates (Cobalt Strike, Ransomware, SQLi, Exfiltration, etc.).
   - Single-scenario trigger or batch bursts (1–20 incidents) with immediate database ingestion and WebSocket broadcast.

8. **Email Notifications & Detection Rules**
   - Configurable trigger rules with cooldown policies (Failed logins burst, Ransomware, Brute force).
   - Safe `SIMULATION MODE` by default; real SMTP credentials protected without exposure.
   - Paginated dispatch logs and interactive test email verification.

---

## 🧪 Running Automated Tests

Run the complete 47-test pytest suite:
```bash
cd backend
PYTHONPATH=. ./venv/bin/pytest -v
```

Tests cover:
- Authentication & JWT issuance
- Role-Based Access Control (RBAC) enforcement
- Incident CRUD & strict lifecycle transitions
- AI triage execution and payload validation
- Playbook simulation and state transitions
- Analytics aggregation correctness
- API key generation and hashed storage
- Security hardening (SQLi payloads, tampered tokens, response headers)
- Full multi-user end-to-end incident response workflow

---

## 📂 Documentation Directory

Detailed technical documents are available in this repository:
- [`ARCHITECTURE.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/ARCHITECTURE.md) — System components, data flows, and architecture diagrams.
- [`API_DOCUMENTATION.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/API_DOCUMENTATION.md) — REST API endpoints, schemas, parameters, and error codes.
- [`DATABASE.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/DATABASE.md) — PostgreSQL / SQLAlchemy schema models, relationships, and migrations.
- [`SECURITY.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/SECURITY.md) — Security mechanisms, RBAC matrix, token security, and audit logging.
- [`AI_WORKFLOW.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/AI_WORKFLOW.md) — AI reasoning architecture, MITRE mapping, and human-in-the-loop controls.
- [`REALTIME.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/REALTIME.md) — WebSocket event schemas and two-browser synchronization.
- [`TESTING.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/TESTING.md) — Test suites, coverage, and execution instructions.
- [`DEPLOYMENT.md`](file:///Users/shashidhar/Downloads/AIACcyber%20copy/DEPLOYMENT.md) — Docker containerization, environment variables, and production deployment.
