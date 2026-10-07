"""
Interactive SOC Playbooks & Incident Checklist Engine for LazySOC.
Standardized Incident Response procedures mapped to NIST SP 800-61r2 and MITRE ATT&CK.
Provides structured workflows, actionable checklists, and ready-to-run CLI commands.
"""

from typing import Dict, Any, List, Optional
import datetime


PLAYBOOKS_DATABASE: Dict[str, Dict[str, Any]] = {
    "phishing": {
        "id": "phishing",
        "title": "Phishing & Business Email Compromise (BEC)",
        "category": "Email & Social Engineering",
        "severity": "HIGH",
        "mitre": "T1566 - Phishing, T1586 - Compromised Accounts",
        "description": "Standard operating procedure for triaging suspicious emails, credential harvesters, malicious attachments, and executive impersonation.",
        "tasks": [
            {
                "id": "phish_1",
                "phase": "Identification",
                "title": "Extract & Inspect RFC 822 Headers & Authentication Posture",
                "description": "Audit SPF, DKIM, and DMARC alignment. Review Received hop headers to pinpoint originating IP and unauthorized relay servers.",
                "command": "# Inspect Mail Headers in PowerShell\nGet-MessageTrace -SenderAddress \"attacker@domain.com\" -StartDate (Get-Date).AddDays(-2)",
                "mitre": "T1566.002",
            },
            {
                "id": "phish_2",
                "phase": "Identification",
                "title": "Harvest Indicators (URLs, Sender Domains, Attachment Hashes)",
                "description": "Extract all embedded URLs, unshorten redirects, and compute SHA256 hashes of any email attachments.",
                "command": "Get-FileHash -Algorithm SHA256 .\\suspicious_attachment.pdf",
                "mitre": "T1204.002",
            },
            {
                "id": "phish_3",
                "phase": "Identification",
                "title": "Determine Exposure Blast Radius & Recipient Clickers",
                "description": "Search email gateways (M365, Google Workspace, Proofpoint) to identify all internal mailboxes that received the phishing message and users who clicked embedded links.",
                "command": "# M365 Threat Explorer Query\nGet-MailDetailDeliveryReport -StartDate (Get-Date).AddDays(-1) -MessageSubject \"Urgent Payment Notice\"",
                "mitre": "T1566",
            },
            {
                "id": "phish_4",
                "phase": "Containment",
                "title": "Purge Malicious Email from All Internal Mailboxes",
                "description": "Execute tenant-wide hard delete of the phishing email across all recipient mailboxes to prevent further user interaction.",
                "command": "# Microsoft 365 Exchange Hard Purge\nNew-ComplianceSearch -Name \"PhishPurge\" -ExchangeLocation All -ContentMatchQuery 'Subject:\"Urgent Payment\"'\nStart-ComplianceSearch -Identity \"PhishPurge\"\nNew-ComplianceSearchAction -SearchName \"PhishPurge\" -Purge -PurgeType HardDelete",
                "mitre": "T1566.001",
            },
            {
                "id": "phish_5",
                "phase": "Containment",
                "title": "Block Malicious Sender, Domains & Payload URLs at Perimeter",
                "description": "Add originating IP, sender domain, and landing URLs to mail gateway blocklist, web proxy, DNS sinkhole, and perimeter firewall.",
                "command": "# Add Tenant Block in Exchange Online\nNew-TenantAllowBlockListItems -ListType Url -Entry \"malicious-login.xyz\" -Block -ExpirationDate (Get-Date).AddDays(90)",
                "mitre": "T1071.001",
            },
            {
                "id": "phish_6",
                "phase": "Eradication",
                "title": "Revoke Active Sessions & Reset Passwords of Interacting Users",
                "description": "For any user who opened attachments, submitted credentials, or authorized OAuth apps, immediately terminate active refresh tokens and rotate passwords.",
                "command": "# Revoke Azure AD / Entra ID Sessions\nRevoke-AzureADUserAllRefreshToken -ObjectId \"target_user@company.com\"\nSet-MsolUserPassword -UserPrincipalName \"target_user@company.com\" -ForceChangePassword $true",
                "mitre": "T1078.004",
            },
            {
                "id": "phish_7",
                "phase": "Eradication",
                "title": "Inspect Mailbox Inbox Rules & Rogue OAuth Enterprise Apps",
                "description": "Check if attacker created covert mailbox forwarding rules, hidden deletion rules, or registered malicious OAuth applications.",
                "command": "# Detect rogue inbox forwarding rules\nGet-InboxRule -Mailbox \"target_user@company.com\" | Select Name, ForwardTo, RedirectTo, DeleteMessage\n# Check OAuth App Consents\nGet-AzureADUserOAuth2PermissionGrant -ObjectId \"target_user@company.com\"",
                "mitre": "T1114.003",
            },
            {
                "id": "phish_8",
                "phase": "Recovery",
                "title": "Enforce MFA Re-Registration & Endpoint AV Scan",
                "description": "Require user to re-authenticate with hardware security key / authenticator app and run full EDR scanner on the victim's endpoint.",
                "command": "Start-MpScan -ScanType FullScan",
                "mitre": "T1556",
            },
            {
                "id": "phish_9",
                "phase": "Recovery",
                "title": "Post-Incident Hardening & Lessons Learned Documentation",
                "description": "Report malicious indicators to abuse registries (VirusTotal, AbuseIPDB, CISA), update DMARC/spam filter rules, and log ticket handover note.",
                "command": "# Log incident notes to Jira / ServiceNow ticket with technical findings.",
                "mitre": "M1031",
            },
        ],
    },
    "ransomware": {
        "id": "ransomware",
        "title": "Ransomware & Destructive Malware Outbreak",
        "category": "Endpoint & Malicious Code",
        "severity": "CRITICAL",
        "mitre": "T1486 - Data Encrypted for Impact, T1489 - Service Stop",
        "description": "Critical emergency containment playbook for active ransomware execution, shadow copy deletion, mass file encryption, and double-extortion threats.",
        "tasks": [
            {
                "id": "rw_1",
                "phase": "Identification",
                "title": "Identify Patient Zero & Ransom Note Extensions",
                "description": "Determine initial encrypted host, locate ransom note (.txt / .html), extract encrypted file extension, and record ransom payment deadline.",
                "command": "Get-ChildItem -Path C:\\ -Filter \"*.README*\" -Recurse -ErrorAction SilentlyContinue | Select FullName, LastWriteTime",
                "mitre": "T1486",
            },
            {
                "id": "rw_2",
                "phase": "Identification",
                "title": "Capture Volatile Memory & Running Malware Process Tree",
                "description": "If host is accessible, capture memory dump and record suspicious parent-child process relationships (e.g. cmd -> powershell -> vssadmin).",
                "command": "Get-CimInstance Win32_Process | Select ProcessId, ParentProcessId, Name, CommandLine | Where-Object { $_.CommandLine -like '*vssadmin*' -or $_.CommandLine -like '*wbadmin*' }",
                "mitre": "T1490",
            },
            {
                "id": "rw_3",
                "phase": "Containment",
                "title": "Immediate Network Isolation of Affected Hosts",
                "description": "Sever host network connectivity via EDR Host Isolation, disable switch port, or apply local host firewall isolation rules immediately.",
                "command": "# Windows Local Firewall Complete Isolation (Block All Outbound/Inbound)\nSet-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block",
                "mitre": "T1041",
            },
            {
                "id": "rw_4",
                "phase": "Containment",
                "title": "Disable Compromised Domain Credentials & Service Accounts",
                "description": "Lock active domain user accounts and service accounts associated with the infected hosts to inhibit lateral movement.",
                "command": "Disable-ADAccount -Identity \"compromised_svc_account\"",
                "mitre": "T1078.002",
            },
            {
                "id": "rw_5",
                "phase": "Containment",
                "title": "Sever Shared Network Drives & Disable SMB File Shares",
                "description": "Temporarily disable network shares and administrative shares (C$, ADMIN$) to prevent ransomware worm spread across file servers.",
                "command": "Stop-Service -Name LanmanServer -Force\nSet-Service -Name LanmanServer -StartupType Disabled",
                "mitre": "T1021.002",
            },
            {
                "id": "rw_6",
                "phase": "Eradication",
                "title": "Terminate Malicious Processes & Hash Ban on EDR",
                "description": "Deploy emergency hash blocklist (SHA256) across the entire fleet via EDR and terminate active malware processes.",
                "command": "Stop-Process -Name \"malware_process\" -Force",
                "mitre": "T1059",
            },
            {
                "id": "rw_7",
                "phase": "Eradication",
                "title": "Inspect & Clean Persistence (Scheduled Tasks, RunKeys, Services)",
                "description": "Enumerate auto-start extensibility points (ASEPs), malicious services, WMI event subscriptions, and registry Run keys.",
                "command": "Get-ScheduledTask | Where-Object { $_.Date -ge (Get-Date).AddDays(-2) }\nGet-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "mitre": "T1053.005",
            },
            {
                "id": "rw_8",
                "phase": "Recovery",
                "title": "Verify Offline & Immutable Backup Integrity",
                "description": "Verify that air-gapped / immutable backups are intact, unencrypted, and free of malware persistence before initiating restore.",
                "command": "# Confirm backup immutable retention lock status with storage administrator.",
                "mitre": "M1053",
            },
            {
                "id": "rw_9",
                "phase": "Recovery",
                "title": "Rebuild / Reimage Affected Endpoints from Clean Media",
                "description": "Do NOT decrypt in-place on untrusted systems. Wipe disk, reimage OS from golden image, patch vulnerabilities, and restore validated data.",
                "command": "# Reimage endpoint and enroll into EDR with updated detection signatures.",
                "mitre": "M1026",
            },
        ],
    },
    "credential_theft": {
        "id": "credential_theft",
        "title": "Compromised Credentials & Account Takeover (ATO)",
        "category": "Identity & Access Management",
        "severity": "HIGH",
        "mitre": "T1078 - Valid Accounts, T1110 - Brute Force / Spraying",
        "description": "Standard operating procedure for detecting and mitigating hijacked accounts, credential stuffing, password spraying, and rogue admin activity.",
        "tasks": [
            {
                "id": "ato_1",
                "phase": "Identification",
                "title": "Analyze Sign-In Telemetry & Impossible Travel Anomalies",
                "description": "Review Entra ID / Okta / Google Workspace authentication logs for anomalous geolocation hops, malicious ASN/hosting providers, and high risk scores.",
                "command": "# Azure AD Sign-in Logs Filter\nGet-AzureADAuditSignInLogs -Filter \"userPrincipalName eq 'user@company.com'\" | Select CreatedDateTime, IPAddress, Location, AppDisplayName, Status",
                "mitre": "T1078.004",
            },
            {
                "id": "ato_2",
                "phase": "Identification",
                "title": "Identify Attacker Source IP & Correlate Threat Intel",
                "description": "Extract the malicious source IP address and triage with VirusTotal and AbuseIPDB in LazySOC to identify known proxy/Tor/VPN exits.",
                "command": "# Check IP reputation and ASN in LazySOC IoC Triage.",
                "mitre": "T1584",
            },
            {
                "id": "ato_3",
                "phase": "Containment",
                "title": "Invalidate All Active Sessions & Refresh Tokens Immediately",
                "description": "Instantly revoke all active web sessions, OAuth tokens, and mobile app tokens to kick the adversary out of active connections.",
                "command": "Revoke-AzureADUserAllRefreshToken -ObjectId \"user@company.com\"\n# AWS IAM Session Revocation\naws iam put-user-policy --user-name Alice --policy-name RevokeOldSessions --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"2026-10-07T00:00:00Z\"}}}]}'",
                "mitre": "T1531",
            },
            {
                "id": "ato_4",
                "phase": "Containment",
                "title": "Reset Password & Temporarily Suspend Account if High Risk",
                "description": "Change account password to high-entropy temporary credential and set require change at next sign-in.",
                "command": "Set-ADUser -Identity \"user\" -ChangePasswordAtLogon $true",
                "mitre": "T1078",
            },
            {
                "id": "ato_5",
                "phase": "Eradication",
                "title": "Audit Rogue MFA Devices & Secondary Auth Methods",
                "description": "Inspect registered authentication methods for attacker-added authenticator apps, rogue phone numbers, or FIDO2 keys.",
                "command": "Get-MgUserAuthenticationMethod -UserId \"user@company.com\"",
                "mitre": "T1556.006",
            },
            {
                "id": "ato_6",
                "phase": "Eradication",
                "title": "Audit Privilege Escalation & Rogue Cloud Resources",
                "description": "Check if attacker granted themselves Global Admin, created new access keys, or modified IAM trust policies.",
                "command": "# Search Audit Logs for role assignments\nGet-AzureADAuditDirectoryLog -Filter \"category eq 'RoleManagement'\"",
                "mitre": "T1098",
            },
            {
                "id": "ato_7",
                "phase": "Recovery",
                "title": "Re-Enroll Phishing-Resistant MFA (FIDO2 / Passkey)",
                "description": "Enforce hardware security key or number-matching authenticator application for subsequent sign-ins.",
                "command": "# Enforce Conditional Access MFA Policy requirement for user group.",
                "mitre": "M1032",
            },
            {
                "id": "ato_8",
                "phase": "Recovery",
                "title": "Threat Hunt Attacker IP Across SIEM / EDR Fleet",
                "description": "Query SIEM (Splunk/Sentinel/CrowdStrike) using LazySOC Query Generator to uncover if the same attacker IP accessed other corporate accounts.",
                "command": "# Use LazySOC 'SIEM Hunting Queries' to search the attacker IP across all firewall & VPN logs.",
                "mitre": "T1078",
            },
        ],
    },
    "c2_exfil": {
        "id": "c2_exfil",
        "title": "Command & Control (C2) & Data Exfiltration",
        "category": "Network Intrusion & C2",
        "severity": "CRITICAL",
        "mitre": "T1071 - Application Layer Protocol, T1041 - Exfiltration Over C2 Channel",
        "description": "Playbook for identifying periodic beaconing, covert DNS tunneling, egress data bursts, and severing adversary C2 communication lines.",
        "tasks": [
            {
                "id": "c2_1",
                "phase": "Identification",
                "title": "Detect Beaconing Interval & Regularity Analysis",
                "description": "Inspect proxy and firewall egress connection timing to calculate jitter and identify periodic beaconing cycles (Cobalt Strike, Sliver, Mythic).",
                "command": "# Bro / Zeek conn.log or firewall flow inspection for fixed connection intervals.",
                "mitre": "T1071.001",
            },
            {
                "id": "c2_2",
                "phase": "Identification",
                "title": "Inspect Suspicious DNS Queries & Tunneling Indicators",
                "description": "Look for high volumes of unique subdomains (FQDNs), TXT record queries with base64/hex payloads, or abnormal NXDOMAIN bursts.",
                "command": "Get-DnsClientCache | Select Entry, Data, TimeToLive | Where-Object { $_.Entry -like '*.xyz' -or $_.Entry -like '*.top' }",
                "mitre": "T1071.004",
            },
            {
                "id": "c2_3",
                "phase": "Containment",
                "title": "Sever Perimeter Egress Channel & Sinkhole C2 Domains",
                "description": "Block destination IP on core edge firewalls and configure internal DNS server to sinkhole or drop the C2 domain.",
                "command": "# Linux iptables emergency drop\niptables -I FORWARD -d 185.220.101.5 -j DROP\niptables -I OUTPUT -d 185.220.101.5 -j DROP",
                "mitre": "T1071",
            },
            {
                "id": "c2_4",
                "phase": "Containment",
                "title": "Isolate Endpoint Establishing Outbound Connection",
                "description": "Identify which local process and PID opened the outbound socket and terminate or isolate the host.",
                "command": "Get-NetTCPConnection -RemoteAddress \"185.220.101.5\" | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess",
                "mitre": "T1049",
            },
            {
                "id": "c2_5",
                "phase": "Eradication",
                "title": "Dump & Terminate Memory-Injected Payload",
                "description": "Use EDR / Sysinternals ProcDump to acquire process memory dump, then kill process tree.",
                "command": "procdump.exe -ma <PID> C:\\evidence_dump.dmp\nStop-Process -Id <PID> -Force",
                "mitre": "T1055",
            },
            {
                "id": "c2_6",
                "phase": "Eradication",
                "title": "Estimate Exfiltrated Data Volume & Affected Assets",
                "description": "Quantify outbound bytes sent to determine whether intellectual property, PII, or credentials were leaked.",
                "command": "# Query firewall traffic logs: sum(bytes_out) by destination_ip over past 14 days.",
                "mitre": "T1048",
            },
            {
                "id": "c2_7",
                "phase": "Recovery",
                "title": "Harden Perimeter Egress Filtering & Restrict Outbound Ports",
                "description": "Block direct egress on non-standard ports (deny all except approved proxies on 80/443).",
                "command": "# Update perimeter firewall rule: Disallow direct outbound internet except via authenticated proxy.",
                "mitre": "M1037",
            },
        ],
    },
    "web_exploit": {
        "id": "web_exploit",
        "title": "Web Application Attack & Webshell Intrusion",
        "category": "Web Security & Cloud",
        "severity": "HIGH",
        "mitre": "T1190 - Exploit Public-Facing App, T1505.003 - Web Shell",
        "description": "SOP for responding to SQL injection, Remote Code Execution (RCE), unauthenticated file uploads, and dropped webshell backdoors.",
        "tasks": [
            {
                "id": "web_1",
                "phase": "Identification",
                "title": "Locate Malicious HTTP Request URI & Status Codes",
                "description": "Scan web server access logs (Nginx, Apache, IIS) for 500/200 anomalies, base64 payloads, or known webshell filenames (cmd.php, b374k).",
                "command": "# Search Nginx Access Logs for webshell interactions\ngrep -E \"(cmd=|whoami|eval\\(|base64_decode|system\\()\" /var/log/nginx/access.log",
                "mitre": "T1190",
            },
            {
                "id": "web_2",
                "phase": "Identification",
                "title": "Scan Webroot for Modified & Newly Created Files",
                "description": "Compare web document root files against golden Git repository commit to identify unauthorized modifications.",
                "command": "git -C /var/www/html status --short\n# Or find files created in the last 2 days\nfind /var/www/html -type f -mtime -2 -name \"*.php\"",
                "mitre": "T1505.003",
            },
            {
                "id": "web_3",
                "phase": "Containment",
                "title": "Block Attacker IP on WAF & Perimeter Firewall",
                "description": "Add the attacking IP address to Cloudflare / AWS WAF / ModSecurity block rules.",
                "command": "# AWS WAF IP Set Update or Cloudflare Firewall Rule\ncurl -X POST \"https://api.cloudflare.com/client/v4/zones/<ZONE>/firewall/access_rules/rules\" -H \"Authorization: Bearer <TOKEN>\" -d '{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"185.220.101.5\"}}'",
                "mitre": "T1190",
            },
            {
                "id": "web_4",
                "phase": "Containment",
                "title": "Disable Script Execution in Upload Directories",
                "description": "Ensure upload directories do not allow executing PHP/ASP/JSP binaries.",
                "command": "# In Nginx location /uploads/ { php-fpm fastcgi_pass disabled; }",
                "mitre": "M1038",
            },
            {
                "id": "web_5",
                "phase": "Eradication",
                "title": "Quarantine & Remove Webshell Files",
                "description": "Move suspicious webshells to an isolated quarantine folder with stripped permissions (chmod 000).",
                "command": "chmod 000 /var/www/html/uploads/backdoor.php\nmv /var/www/html/uploads/backdoor.php /opt/quarantine/",
                "mitre": "T1505.003",
            },
            {
                "id": "web_6",
                "phase": "Eradication",
                "title": "Audit Database & Local Service Accounts for Backdoors",
                "description": "Check if attacker dumped database tables, added admin users, or modified crontab tasks under www-data / nginx.",
                "command": "crontab -u www-data -l\ncat /etc/passwd | grep -E \"www-data|apache|nginx\"",
                "mitre": "T1053.003",
            },
            {
                "id": "web_7",
                "phase": "Recovery",
                "title": "Deploy Security Patch & Rotate Database Credentials",
                "description": "Apply vendor software patches, rebuild clean application containers, and rotate all database passwords.",
                "command": "# Rotate DB credentials in environment configuration and restart application service.",
                "mitre": "M1051",
            },
        ],
    },
}


def get_all_playbooks() -> List[Dict[str, Any]]:
    """Returns list of summary metadata for all playbooks."""
    summary = []
    for pb_id, pb in PLAYBOOKS_DATABASE.items():
        summary.append({
            "id": pb["id"],
            "title": pb["title"],
            "category": pb["category"],
            "severity": pb["severity"],
            "mitre": pb["mitre"],
            "description": pb["description"],
            "total_tasks": len(pb["tasks"]),
            "phases": list(dict.fromkeys(t["phase"] for t in pb["tasks"])),
        })
    return summary


def get_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full playbook with all checklist tasks."""
    return PLAYBOOKS_DATABASE.get(playbook_id)


def generate_playbook_report(
    playbook_id: str,
    completed_task_ids: List[str],
    analyst_name: Optional[str] = "SOC Analyst",
    incident_id: Optional[str] = "INC-SOC-001",
    notes: Optional[str] = "",
    iocs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generates clean Markdown & formatted text checklist report for ticket handover."""
    pb = get_playbook(playbook_id)
    if not pb:
        return {"error": f"Playbook '{playbook_id}' not found."}

    total_tasks = len(pb["tasks"])
    completed_count = len([t for t in pb["tasks"] if t["id"] in completed_task_ids])
    progress_pct = int((completed_count / total_tasks * 100)) if total_tasks else 0

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "============================================================",
        f"LAZYSOC INCIDENT RESPONSE PLAYBOOK EXECUTION AUDIT",
        "============================================================",
        f"Incident ID      : {incident_id}",
        f"Playbook         : {pb['title']}",
        f"Category         : {pb['category']}",
        f"Severity         : {pb['severity']}",
        f"Lead Analyst     : {analyst_name or 'SOC Analyst'}",
        f"Timestamp        : {now_utc}",
        f"Progress Status  : {completed_count}/{total_tasks} Tasks Completed ({progress_pct}%)",
        "============================================================",
        "",
        "INCIDENT CHECKLIST EXECUTION LOG:",
        "------------------------------------------------------------",
    ]

    current_phase = None
    for task in pb["tasks"]:
        phase = task["phase"]
        if phase != current_phase:
            current_phase = phase
            lines.append(f"\n[PHASE: {current_phase.upper()}]")

        is_done = task["id"] in completed_task_ids
        mark = "[X]" if is_done else "[ ]"
        status_text = "COMPLETED" if is_done else "PENDING / IN-PROGRESS"
        lines.append(f"{mark} {task['title']} ({status_text})")
        lines.append(f"    MITRE: {task.get('mitre', 'N/A')}")
        lines.append(f"    Guidance: {task['description']}")

    if iocs and len(iocs):
        lines.append("")
        lines.append("------------------------------------------------------------")
        lines.append("OBSERVED THREAT INDICATORS (IOCs):")
        lines.append("------------------------------------------------------------")
        for ioc in iocs[:25]:
            lines.append(f" - {ioc}")

    if notes:
        lines.append("")
        lines.append("------------------------------------------------------------")
        lines.append("ANALYST INVESTIGATION NOTES:")
        lines.append("------------------------------------------------------------")
        lines.append(notes.strip())

    lines.append("")
    lines.append("============================================================")
    lines.append("Generated by LazySOC Automated Cybersecurity Operations")
    lines.append("============================================================")

    report_text = "\n".join(lines)

    return {
        "incident_id": incident_id,
        "playbook_title": pb["title"],
        "progress_pct": progress_pct,
        "completed_count": completed_count,
        "total_tasks": total_tasks,
        "report_markdown": report_text,
    }
