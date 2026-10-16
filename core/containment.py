"""
Containment & Remediation Script Generator for LazySOC.
Generates ready-to-run CLI commands, firewall blocklists, and host isolation scripts
for Palo Alto PAN-OS, Fortinet FortiOS, Cisco ASA, Linux iptables/nftables,
Windows Defender / PowerShell, and EDR agents (CrowdStrike / Defender).
"""

from typing import List, Dict, Any, Optional
import re


def _sanitize_label(val: str) -> str:
    """Sanitizes an indicator to be used safely in CLI object names."""
    return re.sub(r"[^a-zA-Z0-9_\.-]", "_", val).strip("_")


def generate_containment_scripts(
    iocs: List[Dict[str, Any]],
    rule_name: str = "LAZYSOC_BLOCK",
    zone: str = "untrust",
) -> Dict[str, Any]:
    """
    Generates ready-to-run firewall blocklists and endpoint containment commands
    categorized by platform based on provided triage indicators.
    """
    ips = []
    domains = []
    hashes = []

    for item in iocs:
        val = item.get("ioc") or item.get("value") or ""
        itype = (item.get("type") or item.get("ioc_type") or "").lower()
        verdict = (item.get("verdict") or "").lower()

        # If verdict filter is present, prioritize malicious/suspicious, or take all if none marked
        if not val:
            continue

        if itype in ("ipv4", "ipv6"):
            if not item.get("is_private") and not val.startswith(("10.", "192.168.", "172.16.")):
                ips.append(val)
        elif itype == "domain":
            domains.append(val)
        elif itype == "url":
            # Extract domain from URL
            d = val.replace("hxxps://", "").replace("hxxp://", "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if d and d not in domains:
                domains.append(d)
        elif itype in ("md5", "sha1", "sha256"):
            hashes.append(val)

    # 1. PALO ALTO PAN-OS CLI
    palo_lines = [
        f"# Palo Alto PAN-OS CLI Blocklist ({len(ips)} IPs, {len(domains)} Domains)",
        "configure",
    ]
    palo_obj_names = []
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        palo_obj_names.append(lbl)
        palo_lines.append(f'set address "{lbl}" ip-netmask "{ip}/32" description "LazySOC Malicious Indicator"')
    for dom in domains:
        lbl = f"BL_{_sanitize_label(dom)}"
        palo_obj_names.append(lbl)
        palo_lines.append(f'set address "{lbl}" fqdn "{dom}" description "LazySOC Malicious FQDN"')

    if palo_obj_names:
        palo_lines.append(f'set address-group "{rule_name}_GRP" static [ {" ".join(palo_obj_names)} ]')
        palo_lines.append(
            f'set rulebase security rules "DROP_{rule_name}" to "{zone}" from any destination "{rule_name}_GRP" application any service any action drop log-start yes'
        )
    palo_lines.extend(["commit", "exit"])

    # 2. FORTINET FORTIOS CLI
    forti_lines = [
        f"# Fortinet FortiOS CLI Configuration ({len(ips)} IPs, {len(domains)} Domains)",
        "config firewall address",
    ]
    forti_obj_names = []
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        forti_obj_names.append(lbl)
        forti_lines.append(f'    edit "{lbl}"')
        forti_lines.append(f"        set subnet {ip} 255.255.255.255")
        forti_lines.append('        set comment "LazySOC Malicious IoC"')
        forti_lines.append("    next")
    for dom in domains:
        lbl = f"BL_{_sanitize_label(dom)}"
        forti_obj_names.append(lbl)
        forti_lines.append(f'    edit "{lbl}"')
        forti_lines.append("        set type fqdn")
        forti_lines.append(f'        set fqdn "{dom}"')
        forti_lines.append('        set comment "LazySOC Malicious FQDN"')
        forti_lines.append("    next")
    forti_lines.append("end")

    if forti_obj_names:
        forti_lines.append("config firewall addrgrp")
        forti_lines.append(f'    edit "{rule_name}_GRP"')
        forti_lines.append(f'        set member {" ".join([f"{name}" for name in forti_obj_names])}')
        forti_lines.append("    next")
        forti_lines.append("end")

    # 3. CISCO ASA / FIREPOWER CLI
    cisco_lines = [
        f"# Cisco ASA / Firepower CLI Commands ({len(ips)} IPs)",
    ]
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        cisco_lines.append(f"object network {lbl}")
        cisco_lines.append(f" host {ip}")
        cisco_lines.append(f" description LazySOC_Threat_Triage")
    if ips:
        cisco_lines.append(f"object-group network {rule_name}_GRP")
        for ip in ips:
            lbl = f"BL_{_sanitize_label(ip)}"
            cisco_lines.append(f" network-object object {lbl}")
        cisco_lines.append(f"access-list OUTSIDE_IN line 1 deny ip any object-group {rule_name}_GRP")
        cisco_lines.append(f"access-list INSIDE_OUT line 1 deny ip any object-group {rule_name}_GRP")

    # 4. LINUX IPTABLES & NFTABLES
    iptables_lines = [
        f"#!/usr/bin/env bash",
        f"# Linux iptables / nftables Emergency Containment ({len(ips)} IPs)",
        f"set -e",
    ]
    for ip in ips:
        iptables_lines.append(f"iptables -I INPUT -s {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I OUTPUT -d {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I FORWARD -s {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I FORWARD -d {ip} -j DROP -m comment --comment 'LazySOC-Block'")

    # 5. WINDOWS DEFENDER / POWERSHELL NETWORK BLOCK
    win_fw_lines = [
        f"# PowerShell Windows Advanced Firewall Block Rules ({len(ips)} IPs)",
        f"# Run in elevated Administrator PowerShell",
    ]
    for ip in ips:
        win_fw_lines.append(
            f'New-NetFirewallRule -DisplayName "LazySOC Block Outbound - {ip}" -Direction Outbound -Action Block -RemoteAddress "{ip}" -Description "Malicious C2 Blocked by LazySOC"'
        )
        win_fw_lines.append(
            f'New-NetFirewallRule -DisplayName "LazySOC Block Inbound - {ip}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "Malicious Ingress Blocked by LazySOC"'
        )

    # 6. EDR & HOST ISOLATION SCRIPTS
    edr_lines = [
        f"# Endpoint Detection & Response (EDR) Remediation & Containment Snippets",
        "",
        "# [Option A] Microsoft Defender for Endpoint - Null Route via PowerShell (Instant C2 Severing):",
    ]
    for ip in ips:
        edr_lines.append(f'route add {ip} mask 255.255.255.255 127.0.0.1 metric 1 -p')
    
    edr_lines.extend([
        "",
        "# [Option B] CrowdStrike Falcon Real Time Response (RTR):",
        "# 1. Isolate target host from cloud console:",
        "#    isolate <device_id>",
        "# 2. Kill malicious process running by PID:",
        "#    kill <target_pid>",
        "",
        "# [Option C] Emergency Host Disconnect (Complete Network Cut):",
        "# PowerShell (Disable all network adapters):",
        'Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false',
        "",
        "# Linux Emergency Interface Down:",
        "ip link set eth0 down || ifconfig eth0 down",
    ])

    # 7. HASH BAN LIST (FOR EDR CUSTOM INDICATORS)
    hash_lines = [
        f"# Hash Indicators for EDR Blacklist ({len(hashes)} Hashes)",
    ]
    for h in hashes:
        hash_lines.append(f"{h}")

    return {
        "palo_alto": "\n".join(palo_lines),
        "fortinet": "\n".join(forti_lines),
        "cisco_asa": "\n".join(cisco_lines),
        "iptables": "\n".join(iptables_lines),
        "windows_firewall": "\n".join(win_fw_lines),
        "edr_isolation": "\n".join(edr_lines),
        "hash_blocklist": "\n".join(hash_lines),
        "stats": {
            "total_ips": len(ips),
            "total_domains": len(domains),
            "total_hashes": len(hashes),
        },
    }
