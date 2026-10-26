# Responsible AI & Simulation Workflow — AIAC Cyber

## 1. AI Assistant Philosophy

AIAC Cyber implements an **AI-Assisted** model with strict **Human-in-the-Loop (HITL)** oversight. 

```mermaid
sequenceDiagram
    participant Analyst as SOC Analyst (Human)
    participant Gateway as FastAPI Backend
    participant AI as AI Triage Engine
    participant DB as PostgreSQL
    participant Playbook as Playbook Simulation Engine

    Analyst->>Gateway: POST /api/incidents/{id}/triage
    Gateway->>AI: Synthesize logs, indicators, attack vectors
    AI-->>Gateway: Structured Root Cause, IOCs, MITRE, Recommended Playbook
    Gateway->>DB: Save AI Analysis & Update status to TRIAGED
    Gateway-->>Analyst: Return AI Results with Recommendations
    Note over Analyst: Human Review & Validation
    Analyst->>Gateway: POST /api/incidents/{id}/playbook/execute
    Gateway->>Playbook: Run steps in SIMULATION MODE
    Playbook-->>Gateway: Step results & verification checks
    Gateway->>DB: Update incident status to CONTAINED & Log Audit
    Gateway-->>Analyst: Live Status & Simulation Confirmation
```

---

## 2. Safety & Responsible AI Guardrails

1. **No Autonomous Destructive Execution**: The AI does not execute arbitrary operating system commands autonomously.
2. **Simulation Mode Transparency**: All defensive containment actions are executed in simulated sandbox modes with clear UI labels (`SIMULATION MODE`).
3. **Structured Classification**: Outputs adhere to structured security schemas with confidence intervals and root cause rationale rather than unconstrained text.
4. **MITRE ATT&CK Mapping**: Every triage maps threats directly to standardized adversary tactics and techniques.
