"""
SOC Analyst L1 Toolkit & Investigation Accelerators for LazySOC.
Contains:
1. Windows Event ID & NTSTATUS Error Code Translator
2. LOLBAS / GTFOBins Command Line Explainer
3. Impossible Travel & Risky Sign-in Speed Calculator
4. False Positive & Known-Good Whitelist / CIRCL NSRL Hash Checker
5. IP Infrastructure Classifier (Tor, Datacenter, VPN, Residential)
6. User-Agent & Attack Scanner Dissector
"""

import re
import math
import requests
import datetime
from typing import Dict, Any, List, Optional, Tuple


# ==============================================================================
# 1. WINDOWS EVENT ID & NTSTATUS CODE TRANSLATOR
# ==============================================================================

NTSTATUS_CODES: Dict[str, Dict[str, str]] = {
    "0xC000006D": {
        "name": "STATUS_LOGON_FAILURE",
        "description": "Logon failure: Bad username or authentication information.",
        "soc_context": "The attempted logon is invalid due to bad username or credentials.",
        "risk": "MEDIUM",
        "triage_hint": "Check sub-status code to distinguish bad password vs non-existent user.",
    },
    "0xC0000064": {
        "name": "STATUS_NO_SUCH_USER",
        "description": "The specified user account does not exist.",
        "soc_context": "Attacker trying user enumeration, Kerberoasting, or bruteforce guessing non-existent accounts.",
        "risk": "HIGH",
        "triage_hint": "If multiple distinct usernames appear from the same IP, flag as User Account Enumeration.",
    },
    "0xC000006A": {
        "name": "STATUS_PASSWORD_MUST_CHANGE / BAD_PASSWORD",
        "description": "The user account exists, but the password provided was incorrect.",
        "soc_context": "Typical indicator of Password Guessing or Password Spraying.",
        "risk": "HIGH",
        "triage_hint": "If one password is tried against multiple real accounts, it indicates an active Password Spray.",
    },
    "0xC0000234": {
        "name": "STATUS_ACCOUNT_LOCKED_OUT",
        "description": "The user account has been locked out due to exceeding maximum failed logon attempts.",
        "soc_context": "Brute-force lockout or user forgotten password.",
        "risk": "MEDIUM",
        "triage_hint": "Verify with user if they forgot password or if external source IP is spraying.",
    },
    "0xC0000072": {
        "name": "STATUS_ACCOUNT_DISABLED",
        "description": "The specified account is currently disabled.",
        "soc_context": "Attacker attempting to leverage a dormant, offboarded, or disabled user account.",
        "risk": "HIGH",
        "triage_hint": "Disabled accounts should never authenticate. Escalate if coming from external IP.",
    },
    "0xC0000193": {
        "name": "STATUS_ACCOUNT_EXPIRED",
        "description": "The specified user account has expired.",
        "soc_context": "Contractor or temporary account expired but credentials attempted.",
        "risk": "MEDIUM",
        "triage_hint": "Verify with HR or IT service desk if contract was terminated.",
    },
    "0xC0000071": {
        "name": "STATUS_PASSWORD_EXPIRED",
        "description": "The specified account password has expired.",
        "soc_context": "Standard password expiry policy triggered.",
        "risk": "LOW",
        "triage_hint": "Usually benign unless accompanied by credential stuffing.",
    },
    "0xC0000133": {
        "name": "STATUS_TIME_DIFFERENCE_AT_DC",
        "description": "The clocks between DC and client are too far out of sync (Kerberos clock skew).",
        "soc_context": "Kerberos authentication failed due to time skew (> 5 minutes tolerance).",
        "risk": "LOW",
        "triage_hint": "Check NTP sync on client host.",
    },
    "0xC000006E": {
        "name": "STATUS_ACCOUNT_RESTRICTION",
        "description": "Account restriction prevents logon (e.g., unauthorized workstation or logon hours).",
        "soc_context": "User attempting login outside permitted hours or from unassigned computer.",
        "risk": "MEDIUM",
        "triage_hint": "Check Active Directory user logon hours and permitted workstations.",
    },
    "0xC0000022": {
        "name": "STATUS_ACCESS_DENIED",
        "description": "Access is denied.",
        "soc_context": "Process or token lacks security rights to perform action.",
        "risk": "LOW",
        "triage_hint": "Check file or object ACL permissions.",
    },
    "0x00000000": {
        "name": "STATUS_SUCCESS",
        "description": "Operation completed successfully.",
        "soc_context": "Successful authentication or event completion.",
        "risk": "INFO",
        "triage_hint": "Correlate with subsequent activity to ensure session is legitimate.",
    },
}

LOGON_TYPES: Dict[str, Dict[str, str]] = {
    "2": {
        "name": "Interactive (Physical Console)",
        "description": "User logged on locally at the physical keyboard and screen of the computer.",
        "typical_source": "Local Workstation / Laptop",
        "risk": "LOW (Normal human activity)",
    },
    "3": {
        "name": "Network (SMB, Share, RPC, WinRM)",
        "description": "Access across network to shared folders (SMB/CIFS), printers, or remote RPC/WinRM.",
        "typical_source": "File servers, Domain Controllers, lateral movement tools",
        "risk": "MEDIUM (Common channel for lateral movement like PsExec, Cobalt Strike)",
    },
    "4": {
        "name": "Batch (Scheduled Task)",
        "description": "Logon by a scheduled task, backup agent, or automated batch service.",
        "typical_source": "Windows Task Scheduler, Backup software",
        "risk": "LOW (Verify task name and executable)",
    },
    "5": {
        "name": "Service (Service Control Manager)",
        "description": "Logon by a system service started by the Service Control Manager (SCM).",
        "typical_source": "Installed Windows services",
        "risk": "LOW (Investigate if accompanied by Event 7045 / new service)",
    },
    "7": {
        "name": "Unlock Workstation",
        "description": "Workstation unlocked by user entering credentials after lock screen.",
        "typical_source": "Local desktop",
        "risk": "LOW",
    },
    "8": {
        "name": "NetworkCleartext (Unencrypted)",
        "description": "Logon over network where password was sent in cleartext (e.g. Basic Auth in IIS).",
        "typical_source": "Legacy web apps, non-SSL proxies",
        "risk": "HIGH (Insecure protocol prone to credential sniffing)",
    },
    "9": {
        "name": "NewCredentials (RunAs /netonly)",
        "description": "Caller cloned current token and specified new credentials for outbound network connections.",
        "typical_source": "RunAs /netonly, Mimikatz pass-the-hash, Cobalt Strike make_token",
        "risk": "HIGH (Common attack technique for stealth lateral movement)",
    },
    "10": {
        "name": "RemoteInteractive (Remote Desktop / RDP)",
        "description": "User logged on remotely via Remote Desktop (RDP), Terminal Services, or Remote Assistance.",
        "typical_source": "MSTSC / RDP Client",
        "risk": "HIGH if source IP is external or unexpected workstation",
    },
    "11": {
        "name": "CachedInteractive (Offline Credentials)",
        "description": "User logged on locally using cached credentials without contacting a Domain Controller.",
        "typical_source": "Laptops disconnected from corporate network",
        "risk": "LOW",
    },
}

EVENT_IDS: Dict[str, Dict[str, str]] = {
    "4624": {
        "source": "Security",
        "name": "Successful Account Logon",
        "description": "An account was successfully logged on.",
        "soc_guidance": "Check LogonType (Type 10=RDP, Type 3=SMB/Lateral, Type 9=RunAs token clone). Verify Source IP and Workstation Name.",
    },
    "4625": {
        "source": "Security",
        "name": "Failed Account Logon",
        "description": "An account failed to log on.",
        "soc_guidance": "Examine SubStatus code (0xC0000064 = user enumeration, 0xC000006A = password spray). Check source IP.",
    },
    "4672": {
        "source": "Security",
        "name": "Special Privileges Assigned",
        "description": "Account logged on with superuser rights (e.g. SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege).",
        "soc_guidance": "High privilege token created. Common for Administrator or DA accounts. Check parent process.",
    },
    "4688": {
        "source": "Security",
        "name": "Process Creation",
        "description": "A new process has been created.",
        "soc_guidance": "Check CommandLine, ParentProcessName, and TokenElevationType. Watch for lolbins (certutil, powershell -enc, mshta).",
    },
    "4697": {
        "source": "Security",
        "name": "A Service Was Installed in the System",
        "description": "A new service was registered with the system.",
        "soc_guidance": "Common persistence and lateral movement mechanism (PsExec, malicious drivers). Inspect ServiceFileName.",
    },
    "7045": {
        "source": "System",
        "name": "New Service Installed (PPO)",
        "description": "A new service was installed in the Service Control Manager.",
        "soc_guidance": "High-value IOC for persistence. Check Service Account, ImagePath, and StartType.",
    },
    "4720": {
        "source": "Security",
        "name": "User Account Created",
        "description": "A user account was created in Active Directory or Local SAM.",
        "soc_guidance": "Verify against change management ticket. Unauthorized creation indicates backdoor user.",
    },
    "4728": {
        "source": "Security",
        "name": "Member Added to Security Group",
        "description": "A user was added to a security-enabled global group (e.g. Domain Admins, Enterprise Admins).",
        "soc_guidance": "CRITICAL: Potential privilege escalation. Check TargetUserName, MemberName, and SubjectUserName.",
    },
    "4732": {
        "source": "Security",
        "name": "Member Added to Local Security Group",
        "description": "A user was added to local Administrators group.",
        "soc_guidance": "Potential local privilege escalation. Verify if authorized IT technician.",
    },
    "1102": {
        "source": "Security",
        "name": "The Audit Log Was Cleared",
        "description": "The security event log was intentionally wiped.",
        "soc_guidance": "CRITICAL ALERT: Threat actor anti-forensics defense evasion (T1070.001). Immediate host isolation recommended.",
    },
    "104": {
        "source": "System",
        "name": "Log File Was Cleared",
        "description": "The System log file was cleared.",
        "soc_guidance": "Anti-forensics indicator. Identify user account that performed the clear.",
    },
    "4768": {
        "source": "Security",
        "name": "Kerberos TGT Requested",
        "description": "Kerberos Ticket Granting Ticket (TGT) requested from Domain Controller.",
        "soc_guidance": "Check Result Code. 0x18 = pre-authentication failed (bad password), 0x6 = client not found in AD.",
    },
    "4769": {
        "source": "Security",
        "name": "Kerberos Service Ticket Requested (TGS)",
        "description": "A Kerberos service ticket was requested.",
        "soc_guidance": "Ticket encryption RC4 (0x17) with high volume indicates active Kerberoasting attack (T1558.003).",
    },
    "sysmon-1": {
        "source": "Sysmon",
        "name": "Process Creation",
        "description": "Sysmon monitored process launched with full command line, hash, parent info.",
        "soc_guidance": "Examine CommandLine, Hashes (SHA256), ParentCommandLine, IntegrityLevel.",
    },
    "sysmon-3": {
        "source": "Sysmon",
        "name": "Network Connection Detected",
        "description": "Process initiated an outbound or inbound TCP/UDP connection.",
        "soc_guidance": "Identify process communicating to external IPs. Correlate with C2 beaconing.",
    },
    "sysmon-7": {
        "source": "Sysmon",
        "name": "Image Loaded (DLL)",
        "description": "A module or DLL was loaded by a running process.",
        "soc_guidance": "Detects DLL side-loading, DLL hijacking, or injection of unauthorized modules.",
    },
    "sysmon-8": {
        "source": "Sysmon",
        "name": "CreateRemoteThread",
        "description": "A process created a thread in another process memory space.",
        "soc_guidance": "HIGH RISK: Typical process injection technique (Cobalt Strike, shellcode injection into svchost/explorer).",
    },
    "sysmon-10": {
        "source": "Sysmon",
        "name": "ProcessAccess (LSASS OpenProcess)",
        "description": "A process opened another process with specific access rights.",
        "soc_guidance": "If TargetImage is lsass.exe and GrantedAccess is 0x1010 or 0x1FFFFF, this is LSASS credential dumping.",
    },
    "sysmon-11": {
        "source": "Sysmon",
        "name": "FileCreate",
        "description": "A file was written or created on disk.",
        "soc_guidance": "Detects payload staging in Temp, AppData, or ransomware dropping ransom notes.",
    },
    "sysmon-13": {
        "source": "Sysmon",
        "name": "RegistryEvent (Value Set)",
        "description": "A registry value was modified or created.",
        "soc_guidance": "Check persistence keys: CurrentVersion\\Run, RunOnce, Winlogon, Image File Execution Options.",
    },
    "sysmon-22": {
        "source": "Sysmon",
        "name": "DNSEvent (DNS Query)",
        "description": "A process initiated a DNS lookup.",
        "soc_guidance": "Detects DNS tunneling, C2 lookups, and Newly Registered Domains.",
    },
}


def lookup_windows_event(query: str) -> Dict[str, Any]:
    """
    Translates Windows Event IDs, Logon Types, or NTSTATUS hex error codes.
    Can accept raw codes (e.g. 4625, 0xC000006A, Type 10) or raw log snippets.
    """
    clean_q = query.strip()
    results: Dict[str, Any] = {
        "query": clean_q,
        "matched_events": [],
        "matched_ntstatus": [],
        "matched_logon_types": [],
    }

    # Match NTSTATUS codes (e.g. 0xC000006A or C000006A)
    hex_pattern = re.findall(r"(?:0x)?([cC]0000[0-9a-fA-F]{3}|[0-9a-fA-F]{8})", clean_q)
    for h in hex_pattern:
        formatted_code = "0x" + h.upper()
        if formatted_code in NTSTATUS_CODES:
            item = dict(NTSTATUS_CODES[formatted_code])
            item["code"] = formatted_code
            results["matched_ntstatus"].append(item)

    # Match Event IDs (e.g. 4624, 7045, sysmon 1)
    # Check for direct Event ID numbers
    id_tokens = re.findall(r"\b(\d{1,5})\b", clean_q)
    for num in id_tokens:
        if num in EVENT_IDS:
            item = dict(EVENT_IDS[num])
            item["event_id"] = num
            results["matched_events"].append(item)
        sysmon_key = f"sysmon-{num}"
        if sysmon_key in EVENT_IDS and "sysmon" in clean_q.lower():
            item = dict(EVENT_IDS[sysmon_key])
            item["event_id"] = f"Sysmon {num}"
            results["matched_events"].append(item)

    # Match Logon Types (e.g. Logon Type: 10 or Type 3)
    type_tokens = re.findall(r"(?:logon\s*type|type)\s*[:=]?\s*(\d{1,2})", clean_q, re.IGNORECASE)
    if not type_tokens and clean_q.isdigit() and clean_q in LOGON_TYPES:
        type_tokens = [clean_q]

    for lt in type_tokens:
        if lt in LOGON_TYPES:
            item = dict(LOGON_TYPES[lt])
            item["logon_type"] = lt
            results["matched_logon_types"].append(item)

    return results


# ==============================================================================
# 2. LOLBAS / GTFOBINS COMMAND LINE EXPLAINER
# ==============================================================================

LOLBAS_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "certutil": {
        "binary": "certutil.exe",
        "description": "Windows Certificate Utility. Commonly abused to download files or decode base64 payloads.",
        "mitre_id": "T1105 / T1140",
        "mitre_name": "Ingress Tool Transfer / Deobfuscate & Decode",
        "suspicious_args": [
            ("-urlcache", "Forces download from URL to disk bypassing standard browser caching"),
            ("-split", "Splits download stream, commonly combined with -urlcache to download malware"),
            ("-f", "Forces download overwrite"),
            ("-decode", "Decodes Base64 encoded file into executable binary"),
            ("-encode", "Encodes binary into Base64 for data exfiltration"),
        ],
        "default_risk": "HIGH",
    },
    "bitsadmin": {
        "binary": "bitsadmin.exe",
        "description": "Background Intelligent Transfer Service utility. Abused for stealthy file download.",
        "mitre_id": "T1197",
        "mitre_name": "BITS Jobs",
        "suspicious_args": [
            ("/transfer", "Creates a high-priority background download job"),
            ("/create", "Creates a persistent download task"),
            ("/addfile", "Adds remote URL to download queue"),
        ],
        "default_risk": "HIGH",
    },
    "mshta": {
        "binary": "mshta.exe",
        "description": "Microsoft HTML Application Host. Executes HTML/VBScript/JScript from URLs or command line.",
        "mitre_id": "T1218.005",
        "mitre_name": "Signed Binary Proxy Execution: Mshta",
        "suspicious_args": [
            ("javascript:", "Executes inline JScript code without writing files to disk"),
            ("vbscript:", "Executes inline VBScript code"),
            ("http://", "Downloads and executes remote .hta file"),
            ("https://", "Downloads and executes remote .hta file over TLS"),
        ],
        "default_risk": "CRITICAL",
    },
    "rundll32": {
        "binary": "rundll32.exe",
        "description": "Runs exported functions in 32/64-bit DLLs. Abused to execute malware payloads and scripts.",
        "mitre_id": "T1218.011",
        "mitre_name": "Signed Binary Proxy Execution: Rundll32",
        "suspicious_args": [
            ("shell32.dll", "Can invoke Control_RunDLL to execute malicious control panel files"),
            ("javascript:", "Executes inline script via protocol handler"),
            ("advpack.dll", "Executes remote setup scripts"),
        ],
        "default_risk": "HIGH",
    },
    "regsvr32": {
        "binary": "regsvr32.exe",
        "description": "Registers COM DLLs. Abused to execute remote scripts (Squiblydoo technique).",
        "mitre_id": "T1218.010",
        "mitre_name": "Signed Binary Proxy Execution: Regsvr32",
        "suspicious_args": [
            ("/s", "Silent mode (suppresses prompt dialogs)"),
            ("/n", "Specifies not to call DllRegisterServer"),
            ("/u", "Unregisters server"),
            ("/i:", "Specifies URL or scriptlet to execute (Squiblydoo execution)"),
        ],
        "default_risk": "CRITICAL",
    },
    "wmic": {
        "binary": "wmic.exe",
        "description": "WMI command line utility. Abused for local/remote reconnaissance, process execution, and persistence.",
        "mitre_id": "T1047",
        "mitre_name": "Windows Management Instrumentation",
        "suspicious_args": [
            ("process call create", "Executes a process locally or on a remote target host"),
            ("/node:", "Targets remote machine for lateral movement"),
            ("shadowcopy delete", "Deletes Volume Shadow Copies to prevent ransomware recovery"),
            ("os get", "Enumerates operating system details"),
        ],
        "default_risk": "HIGH",
    },
    "vssadmin": {
        "binary": "vssadmin.exe",
        "description": "Volume Shadow Copy Administration. Primary tool used by ransomware to destroy backups.",
        "mitre_id": "T1490",
        "mitre_name": "Inhibit System Recovery",
        "suspicious_args": [
            ("delete shadows", "RANSOMWARE HALLMARK: Deletes all shadow copies so victim cannot recover files"),
            ("/all", "Targets all shadow volumes"),
            ("/quiet", "Suppresses prompt"),
        ],
        "default_risk": "CRITICAL",
    },
    "schtasks": {
        "binary": "schtasks.exe",
        "description": "Task Scheduler CLI. Abused to establish scheduled persistence or execute elevated jobs.",
        "mitre_id": "T1053.005",
        "mitre_name": "Scheduled Task/Job",
        "suspicious_args": [
            ("/create", "Creates a new persistence job"),
            ("/sc onstart", "Sets task to execute automatically upon system boot"),
            ("/sc onlogon", "Sets task to execute upon user logon"),
            ("/ru system", "Runs task with NT AUTHORITY\\SYSTEM privileges"),
        ],
        "default_risk": "MEDIUM",
    },
    "procdump": {
        "binary": "procdump.exe",
        "description": "Sysinternals process dumper. Frequently abused to dump LSASS memory.",
        "mitre_id": "T1003.001",
        "mitre_name": "OS Credential Dumping: LSASS Memory",
        "suspicious_args": [
            ("-ma", "Full memory dump"),
            ("lsass.exe", "Targets Local Security Authority Subsystem Service to steal NTLM/Kerberos credentials"),
        ],
        "default_risk": "CRITICAL",
    },
    "powershell": {
        "binary": "powershell.exe",
        "description": "Windows PowerShell command environment. Primary vehicle for modern multi-stage attacks.",
        "mitre_id": "T1059.001",
        "mitre_name": "Command and Scripting Interpreter: PowerShell",
        "suspicious_args": [
            ("-enc", "Base64 encoded UTF-16LE command (evasion)"),
            ("-encodedcommand", "Base64 encoded UTF-16LE command"),
            ("-w hidden", "Suppresses command window visibility"),
            ("-windowstyle hidden", "Suppresses command window visibility"),
            ("-nop", "Bypasses user profile scripts"),
            ("-noprofile", "Bypasses user profile scripts"),
            ("-ep bypass", "Bypasses execution policy restrictions"),
            ("downloadstring", "In-memory fileless script download (Net.WebClient)"),
            ("downloadfile", "Downloads file to disk"),
            ("iex", "Invoke-Expression (executes in-memory payload)"),
        ],
        "default_risk": "HIGH",
    },
}


def analyze_command_line(cmd_line: str) -> Dict[str, Any]:
    """
    Parses a raw command line, identifies LOLBAS binaries, flags dangerous
    arguments, correlates with MITRE ATT&CK, and produces an L1 risk verdict.
    """
    clean_cmd = cmd_line.strip()
    if not clean_cmd:
        return {"error": "Command line is empty."}

    matched_binaries: List[Dict[str, Any]] = []
    cmd_lower = clean_cmd.lower()

    # Harvest URLs & IPs inside the command line
    urls = re.findall(r"https?://[^\s'\"`]+", clean_cmd, re.IGNORECASE)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean_cmd)

    highest_risk = "LOW"
    risk_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for key, defs in LOLBAS_DEFINITIONS.items():
        # Match binary name
        if re.search(rf"\b{key}(?:\.exe)?\b", cmd_lower):
            flagged_args = []
            for arg, explanation in defs["suspicious_args"]:
                if arg.lower() in cmd_lower:
                    flagged_args.append({
                        "flag": arg,
                        "explanation": explanation,
                    })

            risk = defs["default_risk"]
            if not flagged_args and risk != "CRITICAL":
                risk = "MEDIUM"

            if risk_weights.get(risk, 1) > risk_weights.get(highest_risk, 1):
                highest_risk = risk

            matched_binaries.append({
                "binary": defs["binary"],
                "description": defs["description"],
                "mitre_id": defs["mitre_id"],
                "mitre_name": defs["mitre_name"],
                "risk": risk,
                "flagged_args": flagged_args,
            })

    # Generic PowerShell obfuscation checks if not already caught
    if "powershell" in cmd_lower and "-enc" in cmd_lower and not matched_binaries:
        highest_risk = "HIGH"

    return {
        "raw_command": clean_cmd,
        "is_lolbas": len(matched_binaries) > 0,
        "overall_risk": highest_risk if matched_binaries else "LOW",
        "matched_tools": matched_binaries,
        "extracted_urls": urls,
        "extracted_ips": ips,
    }


# ==============================================================================
# 3. IMPOSSIBLE TRAVEL & RISKY SIGN-IN CALCULATOR
# ==============================================================================

def _haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Computes great-circle distance between two points in km."""
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return R * c


def calculate_impossible_travel(
    lat1: float,
    lon1: float,
    time1_str: str,
    lat2: float,
    lon2: float,
    time2_str: str,
    loc1_name: str = "Location A",
    loc2_name: str = "Location B",
) -> Dict[str, Any]:
    """
    Evaluates whether two login events represent Impossible Travel based on
    geographic coordinates and timestamps.
    """
    try:
        # Parse ISO or standard timestamps
        def _parse_time(t_str: str) -> datetime.datetime:
            t = t_str.strip().replace("Z", "+00:00")
            for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S"):
                try:
                    return datetime.datetime.strptime(t, fmt)
                except ValueError:
                    pass
            # Fallback for ISO format
            return datetime.datetime.fromisoformat(t)

        dt1 = _parse_time(time1_str)
        dt2 = _parse_time(time2_str)

        delta_seconds = abs((dt2 - dt1).total_seconds())
        delta_hours = max(delta_seconds / 3600.0, 0.0001)

        dist_km = _haversine_distance_km(lat1, lon1, lat2, lon2)
        required_speed_kmh = dist_km / delta_hours

        # Typical Boeing/Airbus cruising speed is ~850-950 km/h
        is_impossible = False
        verdict = "FEASIBLE"
        verdict_color = "emerald"

        if dist_km > 500:
            if required_speed_kmh > 1000.0:
                is_impossible = True
                verdict = "CRITICAL: IMPOSSIBLE TRAVEL CONFIRMED"
                verdict_color = "red"
            elif required_speed_kmh > 700.0:
                verdict = "HIGH: SUSPICIOUS TRAVEL (Near Maximum Jet Speed)"
                verdict_color = "amber"
        elif dist_km > 80 and delta_seconds < 300:
            # 80 km in under 5 minutes (> 960 km/h across towns)
            is_impossible = True
            verdict = "HIGH: RAPID LOCATION HOP (Simultaneous Session / Token Theft)"
            verdict_color = "red"

        return {
            "success": True,
            "location_a": loc1_name,
            "location_b": loc2_name,
            "distance_km": round(dist_km, 1),
            "distance_miles": round(dist_km * 0.621371, 1),
            "elapsed_seconds": int(delta_seconds),
            "elapsed_minutes": round(delta_seconds / 60.0, 1),
            "elapsed_hours": round(delta_hours, 2),
            "required_speed_kmh": round(required_speed_kmh, 1),
            "is_impossible": is_impossible,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "explanation": (
                f"Traveling {round(dist_km, 1)} km in {round(delta_seconds / 60.0, 1)} minutes "
                f"requires sustained speed of {round(required_speed_kmh, 1)} km/h. "
                + ("Commercial passenger aircraft fly at ~850 km/h. This sign-in is physically impossible without VPN / credential compromise." if is_impossible else "Speed is within human travel thresholds.")
            ),
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to compute travel metrics: {str(e)}"}


# ==============================================================================
# 4. FALSE POSITIVE (FP) HELPER & WHITELIST CHECKER
# ==============================================================================

KNOWN_GOOD_DOMAINS = [
    # Microsoft & Azure
    (re.compile(r"(?:^|\.)(?:events\.data\.microsoft\.com|vortex\.data\.microsoft\.com|update\.microsoft\.com|wns\.windows\.com|trafficmanager\.net|azureedge\.net|msftconnecttest\.com|live\.com|office\.com|office365\.com|microsoftonline\.com|sharepoint\.com)$", re.IGNORECASE), "Microsoft Legitimate Telemetry / Cloud Endpoint"),
    # Google & Android
    (re.compile(r"(?:^|\.)(?:1e100\.net|googleusercontent\.com|gstatic\.com|googleapis\.com|google-analytics\.com)$", re.IGNORECASE), "Google Global Infrastructure / CDN"),
    # CDNs & Web Security
    (re.compile(r"(?:^|\.)(?:akamaized\.net|akamaihd\.net|edgekey\.net|cloudflare\.com|cloudflare-dns\.com|fastly\.net|cloudfront\.net)$", re.IGNORECASE), "Legitimate Global Content Delivery Network (CDN)"),
    # Vulnerability Scanners
    (re.compile(r"(?:^|\.)(?:qualys\.com|tenable\.com|rapid7\.com)$", re.IGNORECASE), "Enterprise Vulnerability Scanner Vendor"),
]

KNOWN_RMM_TOOLS = [
    ("anydesk", "AnyDesk Remote Desktop (Legitimate remote support or unauthorized shadow IT)"),
    ("teamviewer", "TeamViewer Remote Access"),
    ("ninjarmm", "NinjaOne / NinjaRMM Enterprise Management"),
    ("atera", "Atera IT Management Agent"),
    ("screenconnect", "ConnectWise ScreenConnect"),
    ("kaseya", "Kaseya VSA Agent"),
    ("psexec", "Sysinternals PsExec (Legitimate IT tool, frequently abused by attackers for lateral movement)"),
]


def check_false_positive_indicators(target: str, target_type: str = "") -> Dict[str, Any]:
    """
    Checks an IP, Domain, or Hash against known enterprise whitelists,
    authorized CDNs, and CIRCL NSRL hash lookup.
    """
    clean_target = target.strip().lower()
    t_type = target_type.lower()

    fp_matches = []

    # 1. Check Known Clean Domains & CDNs
    for pattern, desc in KNOWN_GOOD_DOMAINS:
        if pattern.search(clean_target):
            fp_matches.append({
                "category": "Legitimate Enterprise Cloud / CDN",
                "description": desc,
                "confidence": "HIGH_CONFIDENCE_BENIGN",
            })
            break

    # 2. Check RMM Tools
    for tool_name, desc in KNOWN_RMM_TOOLS:
        if tool_name in clean_target:
            fp_matches.append({
                "category": "Remote Monitoring & Management (RMM)",
                "description": desc,
                "confidence": "DUAL_USE_TOOL (Verify if approved by company IT policy)",
            })

    # 3. Check Hash against CIRCL Hashlookup (NIST NSRL Known Clean Files)
    nsrl_match = None
    if len(clean_target) in (32, 40, 64) and re.fullmatch(r"[a-f0-9]+", clean_target):
        try:
            algo = "sha256" if len(clean_target) == 64 else ("sha1" if len(clean_target) == 40 else "md5")
            resp = requests.get(
                f"https://hashlookup.circl.lu/lookup/{algo}/{clean_target}",
                headers={"User-Agent": "LazySOC-CyberSec/3.0", "Accept": "application/json"},
                timeout=4,
            )
            if resp.status_code == 200:
                h_data = resp.json()
                file_name = h_data.get("FileName") or h_data.get("file_name") or "Standard OS Component"
                product = h_data.get("ProductName") or "NIST NSRL Reference Database"
                nsrl_match = {
                    "is_nsrl_clean": True,
                    "file_name": file_name,
                    "product": product,
                    "note": "Verified Authentic NIST NSRL Operating System Binary (Known Benign Clean File).",
                }
                fp_matches.append({
                    "category": "NIST NSRL Known Clean File",
                    "description": f"Verified benign operating system binary ({file_name} in {product})",
                    "confidence": "DEFINITIVE_FALSE_POSITIVE (Known Good File)",
                })
        except Exception:
            pass

    is_likely_fp = any("BENIGN" in m["confidence"] or "NSRL" in m["category"] for m in fp_matches)

    return {
        "target": target,
        "is_likely_false_positive": is_likely_fp,
        "matches": fp_matches,
        "nsrl_data": nsrl_match,
        "recommendation": (
            "LIKELY FALSE POSITIVE: Indicator belongs to an authentic operating system file or verified enterprise cloud service. Verify change context before closing."
            if is_likely_fp
            else "NO WHITELIST MATCH: Proceed with standard threat enrichment and triage investigation."
        ),
    }


# ==============================================================================
# 5. IP INFRASTRUCTURE CLASSIFIER (TOR, DATACENTER, VPN)
# ==============================================================================

DATACENTER_ASNS = {
    "16509": "Amazon Web Services (AWS)",
    "14618": "Amazon Web Services (AWS)",
    "8075": "Microsoft Azure Infrastructure",
    "15169": "Google Cloud Platform (GCP)",
    "396982": "Google Cloud Platform (GCP)",
    "14061": "DigitalOcean Droplets",
    "24940": "Hetzner Online GmbH",
    "63949": "Akamai / Linode Cloud",
    "16276": "OVH SAS Datacenter",
    "20473": "Choopa / Vultr Cloud",
    "51167": "Contabo GmbH VPS",
}

VPN_KEYWORDS = [
    "mullvad", "nordvpn", "expressvpn", "surfshark", "protonvpn", "private internet access",
    "cyberghost", "ipvanish", "windscribe", "hidemyass", "torguard", "purevpn"
]


def classify_ip_infrastructure(ip_str: str, asn_info: str = "", org_info: str = "") -> Dict[str, Any]:
    """
    Classifies an IP address into infrastructure categories:
    TOR_EXIT_NODE, DATACENTER_CLOUD, COMMERCIAL_VPN, or RESIDENTIAL_BROADBAND.
    """
    clean_ip = ip_str.strip()
    asn_clean = asn_info.lower()
    org_clean = org_info.lower()

    tags = []
    category = "RESIDENTIAL / BROADBAND / UNKNOWN"
    risk_level = "LOW"

    # 1. Tor Exit Node Check (Query official Tor exit node bulk list or DNSBL)
    is_tor = False
    try:
        # Reverse IP octets for tor test query: ip.port.dnsel.torproject.org
        octets = clean_ip.split(".")
        if len(octets) == 4:
            rev_ip = ".".join(reversed(octets))
            import socket
            tor_query = f"{rev_ip}.80.ip-port.exitlist.torproject.org"
            try:
                res = socket.gethostbyname(tor_query)
                if res == "127.0.0.2":
                    is_tor = True
                    tags.append("TOR_EXIT_NODE")
                    category = "TOR ANONYMIZATION NETWORK"
                    risk_level = "CRITICAL"
            except Exception:
                pass
    except Exception:
        pass

    # 2. Datacenter ASN Check
    if not is_tor:
        for asn_num, provider in DATACENTER_ASNS.items():
            if f"as{asn_num}" in asn_clean or asn_num in asn_clean or provider.lower() in org_clean:
                tags.append("PUBLIC_CLOUD_DATACENTER")
                category = f"Public Cloud / Hosting Provider ({provider})"
                risk_level = "MEDIUM"
                break

    # 3. Commercial VPN Check
    if any(vpn in org_clean or vpn in asn_clean for vpn in VPN_KEYWORDS):
        tags.append("COMMERCIAL_VPN")
        category = "Commercial Anonymizing VPN"
        risk_level = "HIGH"

    return {
        "ip": clean_ip,
        "is_tor_exit": is_tor,
        "classification": category,
        "risk_level": risk_level,
        "tags": tags,
        "analyst_guidance": (
            "Traffic originating from Tor or Anonymizing VPNs masks attacker identity. Highly suspicious if communicating with internal services."
            if risk_level in ("HIGH", "CRITICAL")
            else "Standard datacenter or ISP broadband IP. Evaluate against normal user baselines."
        ),
    }


# ==============================================================================
# 6. USER-AGENT & ATTACK SCANNER DISSECTOR
# ==============================================================================

OFFENSIVE_SCANNERS = [
    ("sqlmap", "Sqlmap (Automated SQL Injection Exploit Tool)", "CRITICAL"),
    ("nikto", "Nikto Web Vulnerability Scanner", "HIGH"),
    ("nuclei", "ProjectDiscovery Nuclei Vulnerability Scanner", "CRITICAL"),
    ("masscan", "Masscan (Ultra-fast Internet Port Scanner)", "HIGH"),
    ("nmap", "Nmap Network / NSE Port Scanner", "HIGH"),
    ("gobuster", "Gobuster (Directory & DNS Brute-Forcer)", "HIGH"),
    ("dirbuster", "DirBuster (Web Path Brute-Forcer)", "HIGH"),
    ("ffuf", "FFUF (Fast Web Fuzzer)", "HIGH"),
    ("wpscan", "WPScan (WordPress Vulnerability Scanner)", "HIGH"),
    ("acunetix", "Acunetix Web Vulnerability Scanner", "HIGH"),
    ("nessus", "Tenable Nessus Scanner", "MEDIUM"),
    ("zgrab", "ZGrab Banner Grabber / Scanner", "MEDIUM"),
]

SCRIPT_LIBRARIES = [
    ("python-requests", "Python Requests Library (Scripted HTTP automation)", "MEDIUM"),
    ("python-urllib", "Python standard urllib (Automated script)", "MEDIUM"),
    ("go-http-client", "Go standard HTTP library (Often used by modern offensive CLI tools)", "MEDIUM"),
    ("curl/", "cURL Command-Line Tool (Command-line download / probe)", "MEDIUM"),
    ("wget/", "GNU Wget Download Utility", "MEDIUM"),
    ("aiohttp", "Python Async HTTP Library", "MEDIUM"),
    ("libwww-perl", "Perl LWP Library (Legacy attack scripts)", "HIGH"),
    ("apache-httpclient", "Apache Commons HttpClient", "LOW"),
]

HEADLESS_BROWSERS = [
    ("headlesschrome", "Headless Chrome (Automated browser session / scraping / bot)"),
    ("puppeteer", "Puppeteer Browser Automation"),
    ("selenium", "Selenium Web Driver Automation"),
    ("phantomjs", "PhantomJS Headless WebKit"),
    ("playwright", "Microsoft Playwright Automation"),
]


def dissect_user_agent(ua_string: str) -> Dict[str, Any]:
    """
    Analyzes an HTTP User-Agent string, detecting offensive vulnerability
    scanners, automated scripting libraries, headless browsers, and bot anomalies.
    """
    ua = ua_string.strip()
    if not ua:
        return {
            "user_agent": "",
            "category": "SUSPICIOUS_ANOMALY",
            "verdict": "CRITICAL: EMPTY USER-AGENT",
            "threat_level": "HIGH",
            "explanation": "Legitimate browsers always declare a User-Agent. Empty User-Agents are typical for raw socket malware.",
        }

    ua_lower = ua.lower()

    # 1. Check for Offensive Security Scanners
    for scanner_sig, desc, risk in OFFENSIVE_SCANNERS:
        if scanner_sig in ua_lower:
            return {
                "user_agent": ua,
                "category": "OFFENSIVE_SECURITY_SCANNER",
                "tool_name": scanner_sig.upper(),
                "verdict": f"CRITICAL: {desc}",
                "threat_level": risk,
                "is_malicious": True,
                "explanation": f"Explicit User-Agent signature for {desc}. Strong indicator of active scanning or penetration testing.",
            }

    # 2. Check for Headless Automation Browsers
    for bot_sig, desc in HEADLESS_BROWSERS:
        if bot_sig in ua_lower:
            return {
                "user_agent": ua,
                "category": "HEADLESS_AUTOMATION_BROWSER",
                "tool_name": bot_sig.title(),
                "verdict": f"SUSPICIOUS: {desc}",
                "threat_level": "HIGH",
                "is_malicious": True,
                "explanation": f"Detected headless browser automation framework ({desc}). Common in credential stuffing and bot fraud.",
            }

    # 3. Check for Scripting Libraries
    for lib_sig, desc, risk in SCRIPT_LIBRARIES:
        if lib_sig in ua_lower:
            return {
                "user_agent": ua,
                "category": "SCRIPTING_AUTOMATION_LIBRARY",
                "tool_name": lib_sig,
                "verdict": f"AUTOMATED: {desc}",
                "threat_level": risk,
                "is_malicious": False,
                "explanation": f"Automated HTTP request created via {desc}. Not a standard human web browser.",
            }

    # 4. Check for Outdated / Anomalous signatures
    if "msie 6.0" in ua_lower or "windows nt 5.1" in ua_lower:
        return {
            "user_agent": ua,
            "category": "ANCIENT_SPOOFED_BROWSER",
            "verdict": "SUSPICIOUS: Obsolete Windows XP / IE 6.0 User-Agent",
            "threat_level": "HIGH",
            "is_malicious": True,
            "explanation": "Internet Explorer 6.0 is an obsolete browser commonly hardcoded in legacy malware C2 beacon templates.",
        }

    # 5. Standard Browser
    is_standard = any(b in ua_lower for b in ("mozilla/", "chrome/", "safari/", "firefox/", "edg/"))
    return {
        "user_agent": ua,
        "category": "STANDARD_BROWSER" if is_standard else "UNKNOWN_USER_AGENT",
        "verdict": "BENIGN / NORMAL BROWSER" if is_standard else "INFO: Non-Standard User-Agent",
        "threat_level": "LOW",
        "is_malicious": False,
        "explanation": "Matches standard consumer browser signatures (Chrome, Firefox, Safari, Edge)." if is_standard else "User-Agent does not match major consumer browsers.",
    }
