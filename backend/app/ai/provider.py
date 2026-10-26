"""
AI Triage Provider System (Real & Mock AI Providers) + Chatbot Service
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import json
import logging
import asyncio
from app.core.config import settings

logger = logging.getLogger("ai_provider")


class AIProvider(ABC):
    """Abstract Base Class for Cybersecurity AI Triage Providers."""

    @abstractmethod
    async def triage_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def chat(self, messages: List[Dict[str, str]], context: str = "") -> Dict[str, Any]:
        pass


class MockAIProvider(AIProvider):
    """
    Intelligent Cybersecurity Reasoning Engine for Demonstration and Offline Operation.
    CLEARLY LABELLED AS MOCK — never misrepresented as real AI.
    """

    KNOWLEDGE_BASE = {
        "ransomware": {
            "threat_type": "Ransomware Execution — LockBit 3.0",
            "classification": "CONFIRMED_THREAT",
            "severity_score": 9.8,
            "confidence": 98.5,
            "attack_stage": "Impact & Defense Evasion",
            "root_cause": (
                "The endpoint was compromised via a malicious macro embedded in a spear-phishing attachment. "
                "The decoded PowerShell execution chain initiated LockBit 3.0 ransomware, deleted Volume Shadow Copies (vssadmin), "
                "and began file encryption with .locked extension. A C2 beacon was established to Tor exit node (185.220.101.45). "
                "Lateral movement was attempted across internal SMB shares."
            ),
            "summary": "High-impact LockBit 3.0 ransomware infection with active C2 communication and shadow copy destruction.",
            "iocs": ["185.220.101.45", "powershell.exe -enc JABzAD0ATgBl...", "*.docx.locked", "svchost32.exe (unverified)"],
            "mitre_techniques": [
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
                {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
                {"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"},
                {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
            ],
            "recommendations": [
                "Immediately isolate host network interface via EDR agent.",
                "Terminate process tree PID 4832 and block hash perimeter-wide.",
                "Null-route C2 IP 185.220.101.45 at edge firewalls.",
                "Initiate bare-metal restore from offline immutable backup snapshot.",
            ],
            "recommended_playbook": {
                "name": "Ransomware Host Containment & Recovery",
                "steps": [
                    {"desc": "Isolate infected workstation from network", "cmd": "netsh advfirewall set allprofiles state on"},
                    {"desc": "Kill ransomware process tree", "cmd": "taskkill /F /PID 4832 /T"},
                    {"desc": "Block C2 IP at perimeter firewall", "cmd": "iptables -I OUTPUT -d 185.220.101.45 -j DROP"},
                    {"desc": "Preserve memory dump for forensic analysis", "cmd": "winpmem_mini_x64.exe memdump.raw"},
                ]
            }
        },
        "sqli": {
            "threat_type": "SQL Injection & Data Exfiltration",
            "classification": "CONFIRMED_BREACH",
            "severity_score": 9.2,
            "confidence": 97.0,
            "attack_stage": "Exploitation & Exfiltration",
            "root_cause": (
                "Attacker executed UNION-based SQL injection payloads against the /api/v2/users endpoint. "
                "Database error leakage (ORA-00907) allowed schema enumeration followed by partial exfiltration of user tables. "
                "The endpoint lacked parameterized queries and ORM input validation."
            ),
            "summary": "Targeted UNION-based SQLi against public customer API with confirmed exfiltration of sensitive table rows.",
            "iocs": ["45.155.204.127", "GET /api/v2/users?id=1' OR '1'='1", "UNION SELECT username,password"],
            "mitre_techniques": [
                {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection"},
            ],
            "recommendations": [
                "Apply permanent IP block on 45.155.204.127 at WAF layer.",
                "Deploy hotfix replacing concatenated SQL strings with parameterized bindings.",
                "Audit database transaction log for the full blast radius of exfiltrated records.",
            ],
            "recommended_playbook": {
                "name": "WAF Rule Insertion & SQLi Remediation",
                "steps": [
                    {"desc": "Block attacking IP at WAF and perimeter", "cmd": "waf-cli block-ip --ip 45.155.204.127 --duration permanent"},
                    {"desc": "Inspect exfiltrated record count in web logs", "cmd": "grep '45.155.204.127' /var/log/nginx/access.log | awk '{print $9, $10}'"},
                ]
            }
        },
        "lateral": {
            "threat_type": "Lateral Movement — Pass-the-Hash",
            "classification": "CONFIRMED_THREAT",
            "severity_score": 9.5,
            "confidence": 95.0,
            "attack_stage": "Lateral Movement & Privilege Escalation",
            "root_cause": (
                "NTLM hashes harvested from LSASS memory on WKSTN-DEV-012 were replayed across domain controllers. "
                "Attacker established administrative persistence via scheduled tasks and gained unauthorized access to internal file servers."
            ),
            "summary": "Internal domain compromise leveraging Pass-the-Hash and harvested Domain Admin NTLM hashes.",
            "iocs": ["192.168.1.210", "Mimikatz LSASS access", "Scheduled Task: WindowsUpdate"],
            "mitre_techniques": [
                {"technique_id": "T1550.002", "technique_name": "Pass the Hash", "tactic": "Lateral Movement"},
                {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access"},
            ],
            "recommendations": [
                "Enforce Kerberos-only authentication and disable NTLMv1.",
                "Enable LSA protection (RunAsPPL) across all domain-joined endpoints.",
                "Perform immediate KRBTGT password reset (twice) to invalidate Kerberos tickets.",
            ],
            "recommended_playbook": {
                "name": "Pass-the-Hash Containment & Kerberos Purge",
                "steps": [
                    {"desc": "Isolate compromised host 192.168.1.210", "cmd": "edr-cli isolate --host WKSTN-DEV-012"},
                    {"desc": "Purge active Kerberos/NTLM tickets for domain admins", "cmd": "klist purge"},
                ]
            }
        },
        "bruteforce": {
            "threat_type": "Brute-Force Authentication Attack",
            "classification": "CONFIRMED_THREAT",
            "severity_score": 7.8,
            "confidence": 92.0,
            "attack_stage": "Initial Access — Credential Access",
            "root_cause": (
                "Automated credential-stuffing or brute-force tooling detected against the authentication endpoint. "
                "High request rate from a single IP with multiple invalid password attempts suggests automated attack tooling."
            ),
            "summary": "Brute-force authentication attack detected with multiple failed login attempts in a short time window.",
            "iocs": ["Repeated 401 responses", "High auth request rate", "Single source IP anomaly"],
            "mitre_techniques": [
                {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
            ],
            "recommendations": [
                "Temporarily block the source IP at the perimeter firewall.",
                "Enable account lockout policy after 5 failed attempts.",
                "Verify if any successful logins occurred from the suspect IP after the burst.",
                "Enable MFA for all exposed user accounts.",
            ],
            "recommended_playbook": {
                "name": "Brute-Force Response & Account Protection",
                "steps": [
                    {"desc": "Block attacking IP at WAF", "cmd": "waf-cli block-ip --ip <source_ip> --duration 24h"},
                    {"desc": "Check for successful logins from attacker IP", "cmd": "grep '<source_ip>' /var/log/auth.log | grep 'Accepted'"},
                ]
            }
        },
        "default": {
            "threat_type": "Anomalous Cyber Threat Activity",
            "classification": "POTENTIAL_THREAT",
            "severity_score": 7.4,
            "confidence": 88.0,
            "attack_stage": "Reconnaissance & Initial Access",
            "root_cause": (
                "Heuristic analysis detected anomalous process executions and irregular network communication patterns. "
                "Observed indicators reflect potential post-exploitation activity requiring analyst verification."
            ),
            "summary": "Suspicious behavioral anomaly detected across endpoint and network sensors.",
            "iocs": ["Anomalous egress traffic", "Suspicious child process spawned", "Unverified service ticket"],
            "mitre_techniques": [
                {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
            ],
            "recommendations": [
                "Quarantine affected host while memory forensics are performed.",
                "Review perimeter ingress and egress firewall logs for matching indicators.",
                "Rotate credentials for recently logged-in user accounts.",
            ],
            "recommended_playbook": {
                "name": "Standard Threat Triage & Host Isolation",
                "steps": [
                    {"desc": "Isolate suspect endpoint from local subnet", "cmd": "netsh advfirewall set allprofiles state on"},
                    {"desc": "Capture live memory image", "cmd": "winpmem_mini_x64.exe memdump.raw"},
                ]
            }
        }
    }

    CHAT_RESPONSES = {
        "login_flagged": (
            "**[MOCK AI — SIMULATION MODE]**\n\n"
            "Based on the incident context retrieved from the database, this login was flagged because:\n\n"
            "**Verified facts from database records:**\n"
            "- Multiple failed authentication attempts preceded this login\n"
            "- The login occurred outside normal business hours\n"
            "- Source IP was not in the known-good IP allowlist\n\n"
            "**AI-generated interpretation (not confirmed):**\n"
            "This pattern is consistent with credential-stuffing or brute-force activity followed by a successful compromise. "
            "However, it could also be a legitimate user accessing from a new location.\n\n"
            "**Recommended action:** Verify directly with the account owner and check for any subsequent suspicious activity."
        ),
        "critical_incident": (
            "**[MOCK AI — SIMULATION MODE]**\n\n"
            "I've retrieved the latest critical incidents from the database. Here is a summary:\n\n"
            "**Verified data:**\n"
            "- Critical incidents are those with CVSS-equivalent scores ≥ 9.0\n"
            "- Status transitions are recorded in the audit log\n\n"
            "**Recommended immediate actions:**\n"
            "1. Assign to senior analyst\n"
            "2. Run AI triage to get structured IOC and MITRE mapping\n"
            "3. Execute relevant containment playbook\n\n"
            "I can provide more detail on a specific incident if you give me its ID."
        ),
        "ioc_explain": (
            "**[MOCK AI — SIMULATION MODE]**\n\n"
            "**Indicators of Compromise (IoCs)** are forensic artifacts observed on a network or in an operating system that indicate a potential intrusion.\n\n"
            "**Types found in this system:**\n"
            "- **IP addresses** — Source IPs observed during attack activity\n"
            "- **File hashes** — Malware signatures\n"
            "- **Process names** — Suspicious child processes\n"
            "- **URLs/domains** — C2 callback destinations\n\n"
            "**Important caveat:** IoCs alone do not confirm an attack. They require correlation with behavior and context before classification."
        ),
        "mitre": (
            "**[MOCK AI — SIMULATION MODE]**\n\n"
            "The **MITRE ATT&CK Framework** is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.\n\n"
            "**Structure:**\n"
            "- **Tactics** — The adversary's goal (e.g., Initial Access, Execution, Persistence)\n"
            "- **Techniques** — How the goal is achieved (e.g., T1059 - Command and Scripting Interpreter)\n"
            "- **Sub-techniques** — More specific variations\n\n"
            "This platform maps detected incidents to MITRE techniques to help analysts understand attacker behavior and prioritize defenses."
        ),
        "default": (
            "**[MOCK AI — SIMULATION MODE]**\n\n"
            "I'm the CyberSentinel AI Threat Assistant operating in **mock mode**. I can help you:\n\n"
            "- Explain why an incident or login was flagged\n"
            "- Summarize recent critical incidents\n"
            "- Explain indicators of compromise (IoCs)\n"
            "- Describe MITRE ATT&CK techniques\n"
            "- Suggest defensive steps for specific threats\n"
            "- List unresolved high-severity incidents\n\n"
            "**Note:** In mock mode, responses are pre-configured simulations, not real AI analysis. "
            "Configure a real AI provider (OpenAI, Gemini, Anthropic) via the Settings page for live analysis.\n\n"
            "Try asking: *'Why was this login flagged as suspicious?'* or *'Explain the latest critical incident.'*"
        )
    }

    async def triage_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        text = f"{incident_data.get('title', '')} {incident_data.get('description', '')} {incident_data.get('category', '')}".lower()

        selected_key = "default"
        if "ransomware" in text or "lockbit" in text or "encrypt" in text:
            selected_key = "ransomware"
        elif "sql" in text or "injection" in text or "waf" in text:
            selected_key = "sqli"
        elif "pass-the-hash" in text or "lateral" in text or "ntlm" in text or "mimikatz" in text:
            selected_key = "lateral"
        elif "brute" in text or "credential" in text or "failed login" in text:
            selected_key = "bruteforce"

        template = self.KNOWLEDGE_BASE[selected_key]

        iocs = list(template["iocs"])
        source_ip = incident_data.get("source_ip")
        if source_ip and source_ip not in ("Unknown", "None", "") and source_ip not in iocs:
            iocs.insert(0, source_ip)

        return {
            "provider": "mock",
            "model": "aiac-cyber-triage-v3.0 [SIMULATION MODE]",
            "classification": template["classification"],
            "severity_score": template["severity_score"],
            "confidence": template["confidence"],
            "threat_type": template["threat_type"],
            "attack_stage": template["attack_stage"],
            "root_cause": template["root_cause"],
            "summary": template["summary"],
            "iocs": iocs,
            "mitre_techniques": template["mitre_techniques"],
            "recommendations": template["recommendations"],
            "recommended_playbook": template.get("recommended_playbook"),
            "is_mock": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _parse_incident_context(self, context: str) -> Dict[str, str]:
        parsed = {}
        for line in context.splitlines():
            line_str = line.strip()
            if line_str.startswith("INCIDENT_RECORD:"):
                parsed["id"] = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("Title:"):
                parsed["title"] = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("Severity:"):
                parts = line_str.split("|")
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        parsed[k.strip().lower().replace(" ", "_")] = v.strip()
            elif line_str.startswith("Category:"):
                parts = line_str.split("|")
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        parsed[k.strip().lower().replace(" ", "_")] = v.strip()
            elif line_str.startswith("Source IP:"):
                parts = line_str.split("|")
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        parsed[k.strip().lower().replace(" ", "_")] = v.strip()
            elif line_str.startswith("Confirmed IOCs:"):
                parsed["iocs"] = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("MITRE Techniques:"):
                parsed["mitre"] = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("AI Triage Findings:"):
                parsed["ai_findings"] = line_str.split(":", 1)[1].strip()
        return parsed

    async def chat(self, messages: List[Dict[str, str]], context: str = "") -> Dict[str, Any]:
        """Generate a cybersecurity-focused, evidence-grounded mock chatbot response."""
        last_user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user_msg = m.get("content", "").lower()
                break

        parsed = self._parse_incident_context(context) if context else {}
        has_incident = bool(parsed.get("id"))
        inc_id = parsed.get("id", "INCIDENT")
        inc_title = parsed.get("title", "Security Incident")
        severity = parsed.get("severity", "HIGH")
        category = parsed.get("category", "Threat Activity")
        source_ip = parsed.get("source_ip", "Unknown")
        target = parsed.get("target_system", "Unknown")
        status = parsed.get("status", "INVESTIGATING")
        iocs = parsed.get("iocs", "")
        mitre = parsed.get("mitre", "")

        # 1. Why flagged / trigger reason
        if any(k in last_user_msg for k in ["why", "flagged", "trigger", "reason", "detect"]):
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — SOC THREAT ANALYSIS]**\n\n"
                    f"**Incident Reference:** {inc_id} — {inc_title}\n"
                    f"**Classification:** {severity} | **Lifecycle Status:** {status}\n\n"
                    f"**1. Observed Telemetry (Verified Database Facts):**\n"
                    f"- **Source IP / Ingress Origin:** `{source_ip}`\n"
                    f"- **Target Infrastructure:** `{target}`\n"
                    f"- **Threat Category:** {category}\n"
                    f"{f'- **Confirmed IOCs:** {iocs}' if iocs else '- **Confirmed IOCs:** Telemetry correlation in progress'}\n\n"
                    f"**2. Detection Rationale & Progression:**\n"
                    f"The security monitoring engine flagged this activity because observed telemetry patterns deviated significantly from established network baselines. "
                    f"Observed behavioral indicators correspond to adversary execution targeting `{target}`.\n\n"
                    f"**3. Observed Evidence vs Analytical Hypothesis:**\n"
                    f"- **Observed Facts:** Ingress network telemetry and abnormal process invocations on `{target}` are verified in database logs.\n"
                    f"- **Hypothesis:** Classification as {category} is an analytical assessment. Broader domain compromise or data exfiltration is a hypothesis pending memory forensics."
                )
            else:
                response_text = self.CHAT_RESPONSES["login_flagged"]

        # 2. Evidence / IOCs
        elif any(k in last_user_msg for k in ["evidence", "ioc", "indicator", "proof", "hash"]):
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — EVIDENCE & IOC AUDIT]**\n\n"
                    f"**Incident Reference:** {inc_id} — {inc_title}\n\n"
                    f"**Verified Indicators of Compromise (IOCs):**\n"
                    f"{iocs if iocs else 'No individual IOC hashes recorded yet in database records.'}\n\n"
                    f"**Associated MITRE ATT&CK Techniques:**\n"
                    f"{mitre if mitre else 'T1059 (Command and Scripting Interpreter - Execution)'}\n\n"
                    f"**Telemetry Observations:**\n"
                    f"- Target Asset: `{target}`\n"
                    f"- Source IP: `{source_ip}`\n\n"
                    f"*Note: All artifacts above are verified database records. Do not assume persistence until secondary forensic verification is complete.*"
                )
            else:
                response_text = self.CHAT_RESPONSES["ioc_explain"]

        # 3. Playbook recommendations
        elif any(k in last_user_msg for k in ["playbook", "contain", "remediation", "action", "mitigate"]):
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — DEFENSIVE PLAYBOOK RECOMMENDATION]**\n\n"
                    f"**Recommended Playbook:** {category} Host Containment & Remediation\n"
                    f"**Target System:** `{target}` | **Severity Alignment:** {severity}\n\n"
                    f"**Prerequisites & Required Evidence:**\n"
                    f"- Verified process ID or network connection from `{source_ip}`.\n"
                    f"- Confirmed anomalous telemetry in event stream.\n\n"
                    f"**Ordered Containment Steps:**\n"
                    f"1. **Isolate Network Interface:** Quarantine `{target}` from local subnet to prevent lateral traversal.\n"
                    f"2. **Terminate Malicious Processes:** Kill suspicious process hierarchy.\n"
                    f"3. **Perimeter Block:** Null-route `{source_ip}` at edge firewalls.\n"
                    f"4. **Preserve Memory Dump:** Capture volatile RAM snapshot before system reboot.\n\n"
                    f"**Operational Impact & Safety Notice:**\n"
                    f"Playbook execution will strictly operate in **SIMULATION MODE**. No live production systems, customer traffic, or network interfaces will be disrupted."
                )
            else:
                response_text = (
                    "**[SIMULATED MOCK AI — PLAYBOOK LIBRARY]**\n\n"
                    "Defensive playbooks enforce standardized incident containment in SIMULATION MODE.\n"
                    "To recommend a specific playbook, select or specify an active incident from the dropdown or threat drawer."
                )

        # 4. Related incidents
        elif any(k in last_user_msg for k in ["related", "similar", "history", "previous", "other"]):
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — CORRELATED THREAT INTELLIGENCE]**\n\n"
                    f"**Correlation Pivots for {inc_id}:**\n"
                    f"- **Origin IP:** `{source_ip}`\n"
                    f"- **Target System:** `{target}`\n"
                    f"- **Threat Category:** {category}\n\n"
                    f"**Database Correlation Findings:**\n"
                    f"Verified historical query found related telemetry events matching category `{category}` and target `{target}` in recent logs. "
                    f"Adversary activity shows repeated reconnaissance or execution attempts against infrastructure in this segment.\n\n"
                    f"**Recommendation:** Pivot to Analytics to examine category frequency over the last 30 days."
                )
            else:
                response_text = self.CHAT_RESPONSES["critical_incident"]

        # 5. What to investigate next
        elif any(k in last_user_msg for k in ["investigate", "next", "what should", "steps", "recommend"]):
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — PRIORITIZED SOC INVESTIGATION ROADMAP]**\n\n"
                    f"**Prioritized Next Steps for {inc_id} ({severity}):**\n\n"
                    f"1. **Containment State Verification:** Check whether `{target}` network adapter has been quarantined.\n"
                    f"2. **Telemetry Pivot:** Query edge firewall logs for any secondary callbacks or egress from `{source_ip}` within the last 48 hours.\n"
                    f"3. **Account Authentication Audit:** Review recent authentication events on `{target}` for signs of privilege escalation or new local account creation.\n"
                    f"4. **Execute Playbook Simulation:** Run the recommended {category} defensive playbook to register auditable response actions."
                )
            else:
                response_text = (
                    "**[SIMULATED MOCK AI — GENERAL INVESTIGATION GUIDANCE]**\n\n"
                    "1. Filter incidents by CRITICAL severity in the Incidents view.\n"
                    "2. Run AI Triage on newly ingested events to extract IOCs and MITRE mappings.\n"
                    "3. Select an incident to ground threat assistant queries in verified telemetry."
                )

        # 6. Fallback / general
        else:
            if has_incident:
                response_text = (
                    f"**[SIMULATED MOCK AI — SOC THREAT ASSISTANT]**\n\n"
                    f"**Active Incident Context:** {inc_id} ({inc_title})\n"
                    f"**Category:** {category} | **Target:** `{target}` | **Origin:** `{source_ip}`\n\n"
                    f"I can assist with:\n"
                    f"- **Why was this flagged?** — Detection reason & hypothesis vs evidence\n"
                    f"- **What evidence supports this?** — Confirmed IOCs and MITRE techniques\n"
                    f"- **Which playbook is appropriate?** — Recommended containment steps\n"
                    f"- **Show related incidents** — Correlated threats sharing assets or origin\n"
                    f"- **What should I investigate next?** — Prioritized 4-step SOC action plan"
                )
            else:
                response_text = self.CHAT_RESPONSES["default"]

        return {
            "content": response_text,
            "is_mock": True,
            "provider": "mock",
            "model": "aiac-cyber-chat-v3.0 [SIMULATION MODE]",
        }


class RealAIProvider(AIProvider):
    """
    Production AI Provider using external LLMs (OpenAI, Gemini, Anthropic).
    Falls back gracefully to MockAIProvider if API keys are not provided.
    """

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", provider_name: str = "openai"):
        self.api_key = api_key
        self.model = model
        self.provider_name = provider_name
        self.mock_fallback = MockAIProvider()

    async def triage_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            if settings.DEMO_MODE:
                logger.info("No AI API key supplied; operating in DEMO_MODE with MockAIProvider.")
                return await self.mock_fallback.triage_incident(incident_data)
            raise RuntimeError(f"AI Provider '{self.provider_name}' requires AI_API_KEY in non-demo mode.")

        try:
            import httpx
            result = await self._call_openai_triage(incident_data)
            return result
        except Exception as e:
            logger.error(f"Real AI provider error ({self.provider_name}): {e}")
            if not settings.DEMO_MODE:
                raise RuntimeError(f"AI Provider ({self.provider_name}) request failed: {e}")
            result = await self.mock_fallback.triage_incident(incident_data)
            result["summary"] = f"[SIMULATED FALLBACK] {result['summary']}"
            result["is_mock"] = True
            return result

    async def chat(self, messages: List[Dict[str, str]], context: str = "") -> Dict[str, Any]:
        if not self.api_key:
            if settings.DEMO_MODE:
                return await self.mock_fallback.chat(messages, context)
            raise RuntimeError(f"AI Provider '{self.provider_name}' requires AI_API_KEY in non-demo mode.")

        try:
            import httpx
            result = await self._call_openai_chat(messages, context)
            return result
        except Exception as e:
            logger.error(f"Real AI chat error ({self.provider_name}): {e}")
            if not settings.DEMO_MODE:
                raise RuntimeError(f"AI Provider ({self.provider_name}) request failed: {e}")
            result = await self.mock_fallback.chat(messages, context)
            result["content"] = (
                f"⚠️ **AI Provider ({self.provider_name.upper()}) Error**: {str(e)}\n\n"
                "**[SIMULATED MOCK AI FALLBACK ACTIVATED]**\n\n"
                + result["content"]
            )
            result["is_mock"] = True
            return result

    async def _call_openai_triage(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Call OpenAI API for real incident triage."""
        import httpx

        system_prompt = (
            "You are a senior cybersecurity analyst AI. Analyze the given incident and return a structured JSON response. "
            "The response MUST be valid JSON with these fields: "
            "provider, model, classification, severity_score (0-10), confidence (0-100), threat_type, "
            "attack_stage, root_cause, summary, iocs (array), mitre_techniques (array of {technique_id, technique_name, tactic}), "
            "recommendations (array), is_mock (false). "
            "Do NOT fabricate incidents or threat intelligence. Base analysis only on provided data. "
            "Classification must be one of: CONFIRMED_THREAT, CONFIRMED_BREACH, ATTACK_PREVENTED, POTENTIAL_THREAT, BENIGN, FALSE_POSITIVE"
        )

        user_content = f"Analyze this security incident: {json.dumps(incident_data, default=str)}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.1,
            "max_tokens": 2000,
        }

        async with httpx.AsyncClient(timeout=settings.AI_TIMEOUT_SECONDS) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        # Parse JSON from response
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON block
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                result = json.loads(match.group())
            else:
                raise ValueError("AI response did not contain valid JSON")

        result["provider"] = "openai"
        result["model"] = self.model
        result["is_mock"] = False
        return result

    async def _call_openai_chat(self, messages: List[Dict[str, str]], context: str = "") -> Dict[str, Any]:
        """Call OpenAI API for chat responses."""
        import httpx

        system_prompt = (
            "You are CyberSentinel AI, a senior Tier-3 SOC Threat Assistant. "
            "Maintain a calm, concise, professional, evidence-based cybersecurity tone. "
            "Do NOT use cringe greetings, conversational fluff, emojis, or repetitive phrases like 'Great question!' or 'I\\'m happy to help'. "
            "Help analysts investigate incidents using ONLY the verified database records provided. "
            "Explicitly distinguish between verified observed telemetry (observed facts) and analytical threat hypotheses. "
            "Never claim a threat is contained or investigated unless verified in the database context. "
            "Recommend specific containment playbooks and actionable next steps. "
            "Never expose passwords, secrets, tokens, or unauthorized user data."
        )

        if context:
            system_prompt += f"\n\nVerified incident context from database:\n{context}"

        api_messages = [{"role": "system", "content": system_prompt}] + messages

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": api_messages,
            "temperature": 0.2,
            "max_tokens": 1500,
        }

        async with httpx.AsyncClient(timeout=settings.AI_TIMEOUT_SECONDS) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        return {
            "content": content,
            "is_mock": False,
            "provider": "openai",
            "model": self.model,
        }


def get_ai_provider() -> AIProvider:
    """Factory to instantiate the configured AI Provider."""
    if settings.AI_PROVIDER != "mock":
        if not settings.AI_API_KEY:
            if settings.DEMO_MODE and not settings.is_production:
                logger.warning(
                    f"AI_PROVIDER is set to '{settings.AI_PROVIDER}' but AI_API_KEY is not set in environment. "
                    f"Operating under DEMO_MODE — using MockAIProvider [SIMULATED]."
                )
                return MockAIProvider()
            raise RuntimeError(
                f"AI_PROVIDER is set to '{settings.AI_PROVIDER}' but AI_API_KEY is missing in non-demo environment."
            )
        return RealAIProvider(
            api_key=settings.AI_API_KEY,
            model=settings.AI_MODEL,
            provider_name=settings.AI_PROVIDER,
        )
    return MockAIProvider()
