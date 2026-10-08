"""
Threat Hunting Query Generator & Single-IoC Pivot Engine for LazySOC.
Generates targeted queries for Splunk SPL, Microsoft Sentinel KQL, CrowdStrike Falcon LQL,
Elastic/Kibana DQL, OpenSearch PPL, Suricata IDS, and Sigma Rules.
"""

from typing import Dict, Any, List, Optional
import json


def generate_single_ioc_hunt_queries(ioc: str, ioc_type: str, verdict: Optional[str] = "Malicious") -> Dict[str, str]:
    """
    Generates targeted threat hunting queries for a specific single IoC
    across major SIEM and EDR platforms.
    """
    clean_ioc = ioc.strip()
    i_type = ioc_type.lower()
    verdict_label = (verdict or "Malicious").upper()

    queries = {}

    # 1. SPLUNK (SPL)
    if i_type in ("ipv4", "ipv6"):
        queries["splunk"] = (
            f'index=* earliest=-30d (src_ip="{clean_ioc}" OR dest_ip="{clean_ioc}")\n'
            f'| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, src_ip, dest_ip, dest_port, action\n'
            f'| convert ctime(first_seen) ctime(last_seen)\n'
            f'| sort - count'
        )
    elif i_type in ("domain", "url"):
        d_val = clean_ioc.replace("http://", "").replace("https://", "").split("/")[0]
        queries["splunk"] = (
            f'index=* earliest=-30d (query="*{d_val}*" OR url="*{clean_ioc}*")\n'
            f'| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, src_ip, query, url\n'
            f'| convert ctime(first_seen) ctime(last_seen)\n'
            f'| sort - count'
        )
    elif i_type in ("md5", "sha1", "sha256"):
        queries["splunk"] = (
            f'index=* earliest=-30d (file_hash="{clean_ioc}" OR sha256="{clean_ioc}" OR md5="{clean_ioc}")\n'
            f'| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, file_name, file_path, process_name\n'
            f'| sort - count'
        )
    else:
        queries["splunk"] = f'index=* earliest=-30d "{clean_ioc}" | stats count by host, user, source'

    # 2. MICROSOFT SENTINEL / DEFENDER FOR ENDPOINT (KQL)
    if i_type in ("ipv4", "ipv6"):
        queries["sentinel"] = (
            f'// Sentinel / Defender KQL - Network Communication to {clean_ioc}\n'
            f'let targetIp = "{clean_ioc}";\n'
            f'search in (DeviceNetworkEvents, CommonSecurityLog, DnsEvents) TimeGenerated >= ago(30d)\n'
            f'| where RemoteIP == targetIp or DestinationIP == targetIp or IPAddresses has targetIp\n'
            f'| project TimeGenerated, Type = $table, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, ActionType\n'
            f'| sort by TimeGenerated desc'
        )
    elif i_type in ("domain", "url"):
        d_val = clean_ioc.replace("http://", "").replace("https://", "").split("/")[0]
        queries["sentinel"] = (
            f'// Sentinel / Defender KQL - DNS and Web Traffic to {d_val}\n'
            f'let targetDomain = "{d_val}";\n'
            f'search in (DeviceNetworkEvents, DnsEvents, UrlClickEvents) TimeGenerated >= ago(30d)\n'
            f'| where RemoteUrl has targetDomain or Name has targetDomain or Url has targetDomain\n'
            f'| project TimeGenerated, Type = $table, DeviceName, InitiatingProcessAccountName, RemoteUrl, Name\n'
            f'| sort by TimeGenerated desc'
        )
    elif i_type in ("md5", "sha1", "sha256"):
        queries["sentinel"] = (
            f'// Sentinel / Defender KQL - File Execution / Write for {clean_ioc}\n'
            f'let targetHash = "{clean_ioc.lower()}";\n'
            f'DeviceFileEvents\n'
            f'| where TimeGenerated >= ago(30d)\n'
            f'| where SHA256 == targetHash or MD5 == targetHash\n'
            f'| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, MD5\n'
            f'| sort by TimeGenerated desc'
        )
    else:
        queries["sentinel"] = f'search TimeGenerated >= ago(30d) | where * has "{clean_ioc}"'

    # 3. CROWDSTRIKE FALCON (LQL / Event Search)
    if i_type in ("ipv4", "ipv6"):
        queries["crowdstrike"] = (
            f'# CrowdStrike Falcon - Network Connection\n'
            f'event_simpleName=NetworkConnectIP4 RemoteAddressIP4="{clean_ioc}"\n'
            f'| table _time, ComputerName, UserName, RemoteAddressIP4, RemotePort, ContextProcessId\n'
            f'| sort - _time'
        )
    elif i_type in ("domain", "url"):
        d_val = clean_ioc.replace("http://", "").replace("https://", "").split("/")[0]
        queries["crowdstrike"] = (
            f'# CrowdStrike Falcon - DNS Request & HTTP Activity\n'
            f'event_simpleName=DnsRequest DomainName="*{d_val}*"\n'
            f'| table _time, ComputerName, UserName, DomainName, ContextProcessId\n'
            f'| sort - _time'
        )
    elif i_type in ("md5", "sha1", "sha256"):
        queries["crowdstrike"] = (
            f'# CrowdStrike Falcon - Process Execution by Hash\n'
            f'event_simpleName=ProcessRollup2 (SHA256HashData="{clean_ioc}" OR MD5HashData="{clean_ioc}")\n'
            f'| table _time, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine\n'
            f'| sort - _time'
        )
    else:
        queries["crowdstrike"] = f'"{clean_ioc}" | table _time, ComputerName, UserName, event_simpleName'

    # 4. OPENSEARCH / ELASTICSEARCH (DQL & PPL)
    if i_type in ("ipv4", "ipv6"):
        queries["opensearch"] = (
            f'### OpenSearch Dashboards (DQL / Lucene):\n'
            f'(destination.ip: "{clean_ioc}" OR source.ip: "{clean_ioc}")\n\n'
            f'### OpenSearch PPL:\n'
            f'source = * | where destination.ip = \'{clean_ioc}\' or source.ip = \'{clean_ioc}\'\n'
            f'| stats count() as hits by host.name, user.name, destination.ip, destination.port\n'
            f'| sort - hits'
        )
    elif i_type in ("domain", "url"):
        d_val = clean_ioc.replace("http://", "").replace("https://", "").split("/")[0]
        queries["opensearch"] = (
            f'### OpenSearch Dashboards (DQL / Lucene):\n'
            f'(dns.question.name: "*{d_val}*" OR url.domain: "*{d_val}*" OR url.full: "*{clean_ioc}*")\n\n'
            f'### OpenSearch PPL:\n'
            f'source = * | where dns.question.name like \'%{d_val}%\' or url.domain like \'%{d_val}%\'\n'
            f'| stats count() as hits by host.name, user.name, dns.question.name\n'
            f'| sort - hits'
        )
    elif i_type in ("md5", "sha1", "sha256"):
        queries["opensearch"] = (
            f'### OpenSearch Dashboards (DQL / Lucene):\n'
            f'(file.hash.sha256: "{clean_ioc}" OR process.hash.sha256: "{clean_ioc}" OR file.hash.md5: "{clean_ioc}")\n\n'
            f'### OpenSearch PPL:\n'
            f'source = * | where file.hash.sha256 = \'{clean_ioc}\' or process.hash.sha256 = \'{clean_ioc}\'\n'
            f'| stats count() as hits by host.name, user.name, process.name, file.path'
        )
    else:
        queries["opensearch"] = f'"{clean_ioc}"'

    # 5. SURICATA IDS RULE
    sid_val = 1990001 + (hash(clean_ioc) % 90000)
    if i_type in ("ipv4", "ipv6"):
        queries["suricata"] = (
            f'alert ip any any -> {clean_ioc} any (msg:"LazySOC Alert - Outbound Traffic to {verdict_label} IP {clean_ioc}"; '
            f'classtype:trojan-activity; sid:{sid_val}; rev:1; metadata:created_by LazySOC;)'
        )
    elif i_type in ("domain", "url"):
        d_val = clean_ioc.replace("http://", "").replace("https://", "").split("/")[0]
        queries["suricata"] = (
            f'alert dns any any -> any any (msg:"LazySOC Alert - Suspicious DNS Query for {d_val}"; '
            f'dns.query; content:"{d_val}"; nocase; classtype:bad-unknown; sid:{sid_val}; rev:1; metadata:created_by LazySOC;)'
        )
    elif i_type in ("md5", "sha1", "sha256"):
        queries["suricata"] = (
            f'# Suricata File Hash Match (EVE JSON / Lua engine)\n'
            f'alert http any any -> any any (msg:"LazySOC Alert - Malicious File Download Hash {clean_ioc[:10]}..."; '
            f'file.sha256; content:"{clean_ioc.lower()}"; sid:{sid_val}; rev:1;)'
        )
    else:
        queries["suricata"] = f'# No specific Suricata rule template for type {i_type}'

    return {
        "ioc": clean_ioc,
        "type": i_type,
        "verdict": verdict,
        "queries": queries,
    }
