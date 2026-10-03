"""Slothery - Minimalist IoC Checker & Threat Intelligence Dashboard."""

import streamlit as st
import pandas as pd
import time
from typing import List

from core.config import STATIC_DIR, CACHE_TTL_HOURS
from core.parser import parse_raw_text, parse_uploaded_file, IoCItem
from core.key_manager import (
    KeyManager,
    SERVICE_VT,
    SERVICE_ABUSE,
    STATUS_ACTIVE,
    STATUS_RATE_LIMITED,
    STATUS_EXHAUSTED,
    STATUS_INVALID,
)
from core.clients.virustotal import VirusTotalClient
from core.clients.abuseipdb import AbuseIPDBClient
from core.mail_health import MailHealthChecker
from core.engine import (
    EnrichmentEngine,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_CLEAN,
    VERDICT_UNKNOWN,
)
from core.database import (
    get_all_cached_iocs,
    clear_cache,
    delete_cache_entry,
    get_cache_stats,
    get_scan_history,
)
from core.exporter import export_to_csv, export_to_json

# Page configuration
st.set_page_config(
    page_title="Slothery // IoC Triage",
    page_icon="🦥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load custom CSS
css_file = STATIC_DIR / "styles.css"
if css_file.exists():
    with open(css_file, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize singletons & session state
km = KeyManager()
engine = EnrichmentEngine(km)
mail_checker = MailHealthChecker()

if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "scan_summary" not in st.session_state:
    st.session_state.scan_summary = None
if "selected_ioc" not in st.session_state:
    st.session_state.selected_ioc = None
if "raw_input_text" not in st.session_state:
    st.session_state.raw_input_text = ""

# Sample IoC dataset for testing
SAMPLE_IOCS = """# Malicious and Defanged Indicators (Sample)
118[.]25[.]6[.]39
185.220.101.5
hxxps://malware-drop[.]xyz/payload.exe
attacker-c2[.]online
# Clean public DNS & Domains
1.1.1.1
google.com
# Local / Private RFC1918
192.168.1.105
# Malware file hashes (WannaCry & Emotet samples)
ed01ebf83434a16f6003bc90ab3a145b81db813363f49e64bc87da54a07a1222
84c82835a5d21bbcf75a61706d8ab549
"""

# ==========================================
# SIDEBAR: Keys & Settings
# ==========================================
with st.sidebar:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
            <span style="font-size:1.8rem; filter:drop-shadow(0 0 8px #00f2fe);">🦥</span>
            <div>
                <div style="font-weight:700; font-size:1.15rem; letter-spacing:0.04em; color:#f1f5f9;">SLOTHERY</div>
                <div style="font-size:0.75rem; color:#94a3b8; font-family:'JetBrains Mono';">IoC THREAT ENRICHMENT</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # API Key Pool Status
    st.markdown("##### ⚡ API Key Pool Status")
    pool_counts = km.get_pool_counts()

    # VirusTotal key status widget
    vt_info = pool_counts[SERVICE_VT]
    st.markdown(
        f"""
        <div class="key-pool-card">
            <div class="key-pool-header">
                <span>VirusTotal API v3</span>
                <span style="color:#00f2fe; font-family:'JetBrains Mono';">{vt_info['total']} keys</span>
            </div>
            <div class="key-pool-stats">
                <span style="color:#10b981;">● {vt_info['active']} ready</span> &nbsp;|&nbsp; 
                <span style="color:#f59e0b;">● {vt_info['throttled']} cool</span> &nbsp;|&nbsp; 
                <span style="color:#ef4444;">● {vt_info['dead']} off</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # AbuseIPDB key status widget
    abuse_info = pool_counts[SERVICE_ABUSE]
    st.markdown(
        f"""
        <div class="key-pool-card">
            <div class="key-pool-header">
                <span>AbuseIPDB API v2</span>
                <span style="color:#00f2fe; font-family:'JetBrains Mono';">{abuse_info['total']} keys</span>
            </div>
            <div class="key-pool-stats">
                <span style="color:#10b981;">● {abuse_info['active']} ready</span> &nbsp;|&nbsp; 
                <span style="color:#f59e0b;">● {abuse_info['throttled']} cool</span> &nbsp;|&nbsp; 
                <span style="color:#ef4444;">● {abuse_info['dead']} off</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Expandable Key Manager
    with st.expander("🔑 Add / Manage API Keys", expanded=False):
        st.markdown("**Add API Key**")
        svc_choice = st.selectbox(
            "Service",
            [SERVICE_VT, SERVICE_ABUSE],
            format_func=lambda s: "VirusTotal" if s == SERVICE_VT else "AbuseIPDB",
        )
        new_key_input = st.text_input("API Key", type="password", placeholder="Enter key...")
        
        col_add, col_test = st.columns([1, 1])
        with col_add:
            if st.button("➕ Add Key", use_container_width=True):
                if new_key_input:
                    ok, msg = km.add_key(svc_choice, new_key_input)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
                else:
                    st.warning("Please enter a key.")

        st.markdown("---")
        st.markdown("**Current Pool Keys**")
        for svc in [SERVICE_VT, SERVICE_ABUSE]:
            svc_name = "VirusTotal" if svc == SERVICE_VT else "AbuseIPDB"
            st.caption(f"**{svc_name} Keys**")
            entries = km.get_service_summary(svc)
            if not entries:
                st.markdown(f"<span style='color:#64748b; font-size:0.75rem;'>No {svc_name} keys in pool</span>", unsafe_allow_html=True)
            for e in entries:
                col_k1, col_k2 = st.columns([3, 1])
                with col_k1:
                    status_color = "#10b981" if e["status"] == STATUS_ACTIVE else ("#f59e0b" if e["status"] == STATUS_RATE_LIMITED else "#ef4444")
                    st.markdown(
                        f"""
                        <div class="key-item-row">
                            <span>{e['key_masked']}</span>
                            <span style="color:{status_color}; font-size:0.7rem;">[{e['status']}]</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with col_k2:
                    if st.button("✕", key=f"del_{svc}_{e['key_raw']}", help="Remove key"):
                        km.remove_key(svc, e["key_raw"])
                        st.rerun()

    st.markdown("---")

    # Global Settings
    st.markdown("##### ⚙️ Engine Settings")
    use_cache_toggle = st.toggle("Enable Local SQLite Cache", value=True, help="Avoid redundant API lookups for previously checked indicators.")
    ttl_hours_slider = st.slider("Cache TTL (hours)", min_value=1, max_value=168, value=CACHE_TTL_HOURS)
    skip_private_toggle = st.toggle("Filter RFC1918 Private IPs", value=True, help="Mark internal/private LAN IPs as unroutable without querying APIs.")
    auto_throttle_toggle = st.toggle("Smart Throttling (Auto-wait)", value=True, help="Smoothly pause and wait if all API keys temporarily hit rate limits.")
    defang_export_toggle = st.toggle("Defang Exported Indicators", value=True, help="Export indicators with [.] to prevent accidental link opening.")

# ==========================================
# MAIN APP BODY
# ==========================================

# Minimal Hero Title
st.markdown(
    """
    <div class="brand-container">
        <div class="brand-logo">🦥</div>
        <div>
            <h1 class="brand-title">SLOTHERY // IoC THREAT ENRICHMENT</h1>
            <div class="brand-subtitle">Fast, resilient threat intelligence lookup with multi-key rotation and smart throttling.</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_scan, tab_mail, tab_cache, tab_diagnostics = st.tabs([
    "🎯 IoC Scanner",
    "🛡️ Mail Health Check",
    "💾 Local Cache & History",
    "📊 API Health & Quotas",
])

# ------------------------------------------
# TAB 1: SCANNER
# ------------------------------------------
with tab_scan:
    # Input section
    col_input, col_file = st.columns([3, 2])

    with col_input:
        input_text = st.text_area(
            "Paste Raw / Defanged Indicators or Logs",
            value=st.session_state.raw_input_text,
            height=160,
            placeholder="Paste mixed indicators here...\ne.g. 1[.]1[.]1[.]1\n185.220.101.5\ned01ebf83434a16f6003bc90ab3a145b81db813363f49e64bc87da54a07a1222\nattacker-c2[.]online\nhxxps://malware-drop[.]xyz/payload.exe",
            help="Supports IPv4, IPv6, MD5, SHA1, SHA256, Domains, URLs. Automatically removes defang characters like [.] and hxxp.",
        )

        col_sample, col_clear = st.columns([1, 1])
        with col_sample:
            if st.button("🧪 Load Sample Indicators"):
                st.session_state.raw_input_text = SAMPLE_IOCS
                st.rerun()
        with col_clear:
            if st.button("🧹 Clear Input"):
                st.session_state.raw_input_text = ""
                st.session_state.scan_results = []
                st.session_state.scan_summary = None
                st.session_state.selected_ioc = None
                st.rerun()

    with col_file:
        st.markdown("**Or Upload Batch File**")
        uploaded_file = st.file_uploader(
            "Upload .txt or .csv file",
            type=["txt", "csv"],
            help="Upload a file containing IPs, hashes, domains, or URLs.",
        )
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            parsed_from_file = parse_uploaded_file(file_bytes, uploaded_file.name)
            st.info(f"Loaded {len(parsed_from_file)} indicators from `{uploaded_file.name}`")

    # Parse IoCs
    parsed_items: List[IoCItem] = []
    if uploaded_file is not None:
        parsed_items = parse_uploaded_file(file_bytes, uploaded_file.name)
    elif input_text:
        parsed_items = parse_raw_text(input_text)

    # Display detected indicator pills
    if parsed_items:
        ip_count = sum(1 for x in parsed_items if x.ioc_type in ("ipv4", "ipv6"))
        hash_count = sum(1 for x in parsed_items if x.ioc_type in ("md5", "sha1", "sha256"))
        dom_count = sum(1 for x in parsed_items if x.ioc_type == "domain")
        url_count = sum(1 for x in parsed_items if x.ioc_type == "url")
        private_count = sum(1 for x in parsed_items if x.is_private)

        st.markdown(
            f"""
            <div style="display:flex; flex-wrap:wrap; gap:8px; margin: 10px 0 16px 0; align-items:center;">
                <span style="font-size:0.8rem; color:#94a3b8; font-weight:600;">DETECTED:</span>
                {f'<span class="badge badge-clean"><span class="badge-dot"></span>{ip_count} IPs</span>' if ip_count else ''}
                {f'<span class="badge badge-suspicious"><span class="badge-dot"></span>{hash_count} Hashes</span>' if hash_count else ''}
                {f'<span class="badge" style="background:rgba(168,85,247,0.15); color:#d8b4fe; border:1px solid rgba(168,85,247,0.35);"><span class="badge-dot" style="background:#a855f7;"></span>{dom_count} Domains</span>' if dom_count else ''}
                {f'<span class="badge" style="background:rgba(6,182,212,0.15); color:#a5f3fc; border:1px solid rgba(6,182,212,0.35);"><span class="badge-dot" style="background:#06b6d4;"></span>{url_count} URLs</span>' if url_count else ''}
                {f'<span class="badge badge-unknown"><span class="badge-dot"></span>{private_count} Private IPs</span>' if private_count else ''}
                <span style="font-size:0.75rem; color:#64748b; font-family:\'JetBrains Mono\'; margin-left:auto;">Total: {len(parsed_items)} items</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Primary Action Button
    start_scan = st.button("🚀 Start Threat Intelligence Enrichment", type="primary", use_container_width=True, disabled=(len(parsed_items) == 0))

    if start_scan and parsed_items:
        progress_bar = st.progress(0.0)
        status_box = st.empty()
        results_container = []

        total_items = len(parsed_items)
        for event in engine.scan_items(
            items=parsed_items,
            use_cache=use_cache_toggle,
            ttl_hours=ttl_hours_slider,
            skip_private_ips=skip_private_toggle,
            auto_throttle=auto_throttle_toggle,
        ):
            if event["type"] == "progress":
                idx = event["index"]
                pct = idx / total_items
                progress_bar.progress(pct)
                status_box.markdown(
                    f"<span style='font-family:JetBrains Mono; font-size:0.85rem; color:#00f2fe;'>Scanning [{idx}/{total_items}]: <code>{event['current_ioc']}</code> ({event['current_type'].upper()})</span>",
                    unsafe_allow_html=True,
                )

            elif event["type"] == "item_result":
                results_container.append(event["data"])

            elif event["type"] == "complete":
                st.session_state.scan_results = results_container
                st.session_state.scan_summary = event["summary"]
                progress_bar.empty()
                status_box.empty()
                st.toast("Scan successfully completed!", icon="✅")
                st.rerun()

    # Results Section
    if st.session_state.scan_results:
        summary = st.session_state.scan_summary or {
            "total": len(st.session_state.scan_results),
            "malicious": sum(1 for r in st.session_state.scan_results if r["verdict"] == VERDICT_MALICIOUS),
            "suspicious": sum(1 for r in st.session_state.scan_results if r["verdict"] == VERDICT_SUSPICIOUS),
            "clean": sum(1 for r in st.session_state.scan_results if r["verdict"] == VERDICT_CLEAN),
            "unknown": sum(1 for r in st.session_state.scan_results if r["verdict"] == VERDICT_UNKNOWN),
        }

        # Metric Cards
        st.markdown(
            f"""
            <div class="metrics-grid">
                <div class="metric-card total">
                    <div class="metric-title">Total Checked</div>
                    <div class="metric-val">{summary['total']}</div>
                </div>
                <div class="metric-card malicious">
                    <div class="metric-title">Malicious</div>
                    <div class="metric-val">{summary['malicious']}</div>
                </div>
                <div class="metric-card suspicious">
                    <div class="metric-title">Suspicious</div>
                    <div class="metric-val">{summary['suspicious']}</div>
                </div>
                <div class="metric-card clean">
                    <div class="metric-title">Clean</div>
                    <div class="metric-val">{summary['clean']}</div>
                </div>
                <div class="metric-card unknown">
                    <div class="metric-title">Unknown / Private</div>
                    <div class="metric-val">{summary['unknown']}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Filters and Export row
        col_filter, col_search, col_exp_csv, col_exp_json = st.columns([2, 3, 2, 2])

        with col_filter:
            verdict_filter = st.selectbox(
                "Filter Verdict",
                ["All Verdicts", VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_CLEAN, VERDICT_UNKNOWN],
            )

        with col_search:
            search_query = st.text_input("Search Indicator", placeholder="Filter by IP, hash, or ASN...")

        # Apply filters
        filtered_results = st.session_state.scan_results
        if verdict_filter != "All Verdicts":
            filtered_results = [r for r in filtered_results if r["verdict"] == verdict_filter]
        if search_query:
            q = search_query.lower()
            filtered_results = [
                r for r in filtered_results
                if q in r["ioc"].lower() or q in r.get("notes", "").lower() or q in r["type"].lower()
            ]

        # Export buttons
        csv_data = export_to_csv(st.session_state.scan_results, defang_output=defang_export_toggle)
        json_data = export_to_json(st.session_state.scan_results, defang_output=defang_export_toggle)

        with col_exp_csv:
            st.download_button(
                label="📥 Export CSV",
                data=csv_data,
                file_name="slothery_ioc_report.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with col_exp_json:
            st.download_button(
                label="📥 Export JSON",
                data=json_data,
                file_name="slothery_ioc_report.json",
                mime="application/json",
                use_container_width=True,
            )

        # Table Display
        table_rows = []
        for r in filtered_results:
            table_rows.append({
                "Verdict": r["verdict"],
                "Indicator": r["ioc"],
                "Type": r["type"].upper(),
                "VirusTotal": r.get("vt_stats", "N/A"),
                "AbuseIPDB": r.get("abuse_score", "N/A"),
                "Notes": r.get("notes", ""),
                "Cache": "⚡ Cached" if r.get("is_cached") else "Live",
            })

        df = pd.DataFrame(table_rows)

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Verdict": st.column_config.TextColumn("Verdict", width="small"),
                "Indicator": st.column_config.TextColumn("Indicator", width="large"),
                "Type": st.column_config.TextColumn("Type", width="small"),
                "VirusTotal": st.column_config.TextColumn("VirusTotal", width="medium"),
                "AbuseIPDB": st.column_config.TextColumn("AbuseIPDB", width="medium"),
                "Notes": st.column_config.TextColumn("Notes", width="large"),
                "Cache": st.column_config.TextColumn("Source", width="small"),
            },
        )

        # Drill-Down Detail Inspector
        st.markdown("#### 🔍 Indicator Deep Dive")
        ioc_options = [r["ioc"] for r in filtered_results]
        if ioc_options:
            selected = st.selectbox("Select indicator to inspect full threat telemetry:", ioc_options)
            chosen_item = next((r for r in filtered_results if r["ioc"] == selected), None)

            if chosen_item:
                col_d1, col_d2 = st.columns([1, 1])

                with col_d1:
                    st.markdown(f"**Target:** `{chosen_item['ioc']}` ({chosen_item['type'].upper()})")
                    verdict_cls = chosen_item["verdict"].lower()
                    st.markdown(
                        f"""
                        <div style="margin: 8px 0 14px 0;">
                            <span class="badge badge-{verdict_cls}"><span class="badge-dot"></span>{chosen_item['verdict']}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**Summary:** {chosen_item.get('notes', 'N/A')}")
                    if chosen_item.get("is_cached"):
                        st.caption(f"⚡ Loaded from local SQLite cache (updated: {chosen_item.get('updated_at', 'recently')})")

                with col_d2:
                    # AbuseIPDB telemetry
                    abuse_data = chosen_item.get("abuse_data")
                    if abuse_data and abuse_data.get("success"):
                        ad = abuse_data.get("data", {})
                        st.markdown(
                            f"""
                            <div style="background:#111622; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px; margin-bottom:10px;">
                                <div style="font-weight:600; color:#00f2fe; margin-bottom:6px;">AbuseIPDB Telemetry</div>
                                <div style="font-size:0.85rem;">Confidence Score: <b>{ad.get('abuse_confidence_score')}%</b></div>
                                <div style="font-size:0.85rem;">Total Reports: <b>{ad.get('total_reports')}</b></div>
                                <div style="font-size:0.85rem;">ISP: <b>{ad.get('isp')}</b> ({ad.get('country_name')})</div>
                                <div style="font-size:0.85rem;">Usage Type: <b>{ad.get('usage_type')}</b></div>
                                <div style="font-size:0.85rem;">Last Reported: <b>{ad.get('last_reported_at') or 'Never'}</b></div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    # URLhaus telemetry
                    urlhaus_data = chosen_item.get("urlhaus_data")
                    if urlhaus_data and urlhaus_data.get("found"):
                        st.markdown(
                            f"""
                            <div style="background:#111622; border:1px solid rgba(239,68,68,0.4); border-radius:8px; padding:12px; margin-bottom:10px;">
                                <div style="font-weight:600; color:#ef4444; margin-bottom:6px;">abuse.ch URLhaus Telemetry</div>
                                <div style="font-size:0.85rem;">Status: <b style="color:#ef4444;">{urlhaus_data.get('url_status', 'FLAGGED').upper()}</b></div>
                                <div style="font-size:0.85rem;">Threat: <b>{urlhaus_data.get('threat', 'Malware Download')}</b></div>
                                {f"<div style='font-size:0.85rem;'>Tags: {', '.join(urlhaus_data.get('tags', []))}</div>" if urlhaus_data.get('tags') else ''}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    # Mail Health telemetry for domains
                    mail_health = chosen_item.get("mail_health")
                    if mail_health:
                        r_color = "#10b981" if mail_health["rating"] == "PROTECTED" else ("#f59e0b" if mail_health["rating"] == "PARTIALLY_PROTECTED" else "#ef4444")
                        st.markdown(
                            f"""
                            <div style="background:#111622; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px; margin-bottom:10px;">
                                <div style="display:flex; justify-content:space-between;">
                                    <span style="font-weight:600; color:#00f2fe;">Mail Health & Spoof Posture</span>
                                    <span style="font-weight:bold; color:{r_color};">Score: {mail_health['score']}/100</span>
                                </div>
                                <div style="font-size:0.85rem; margin-top:4px;">MX Provider: <b>{mail_health.get('mx', {}).get('provider', 'None')}</b></div>
                                <div style="font-size:0.85rem;">SPF Status: <b>{mail_health.get('spf', {}).get('status', 'MISSING')}</b></div>
                                <div style="font-size:0.85rem;">DMARC Policy: <b>{mail_health.get('dmarc', {}).get('policy', 'none').upper()}</b></div>
                                <div style="font-size:0.8rem; color:{r_color}; margin-top:2px;">{mail_health['verdict']}</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    # VirusTotal telemetry
                    vt_data = chosen_item.get("vt_data")
                    if vt_data and vt_data.get("success") and not vt_data.get("not_found"):
                        stats = vt_data.get("stats", {})
                        st.markdown(
                            f"""
                            <div style="background:#111622; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px;">
                                <div style="font-weight:600; color:#00f2fe; margin-bottom:6px;">VirusTotal Telemetry</div>
                                <div style="font-size:0.85rem;">Detections: <span style="color:#ef4444; font-weight:bold;">{stats.get('malicious', 0)} malicious</span>, <span style="color:#f59e0b;">{stats.get('suspicious', 0)} suspicious</span></div>
                                <div style="font-size:0.85rem;">Harmless / Undetected: {stats.get('harmless', 0)} / {stats.get('undetected', 0)}</div>
                                {f"<div style='font-size:0.85rem;'>Threat Classification: <b>{vt_data.get('threat_label')}</b></div>" if vt_data.get('threat_label') else ''}
                                {f"<div style='font-size:0.85rem;'>Registrar: <b>{vt_data.get('registrar')}</b></div>" if vt_data.get('registrar') else ''}
                                {f"<div style='font-size:0.85rem;'>File Type: <b>{vt_data.get('file_type')}</b> (Size: {vt_data.get('size')} bytes)</div>" if vt_data.get('size') else ''}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                # Raw JSON expander
                with st.expander("📄 Raw API Payloads"):
                    st.json(chosen_item)

# ------------------------------------------
# TAB 2: MAIL HEALTH & SPOOF POSTURE
# ------------------------------------------
with tab_mail:
    st.markdown("#### 🛡️ Email Deliverability & Anti-Spoofing Audit")
    st.caption("Inspect MX records, SPF mechanism, and DMARC enforcement policies to identify email spoofing risks.")

    col_m_input, col_m_btn = st.columns([4, 1])
    with col_m_input:
        mail_domain = st.text_input("Target Domain", placeholder="e.g. google.com, microsoft.com, yourdomain.com", label_visibility="collapsed")
    with col_m_btn:
        run_mail = st.button("Audit Domain", type="primary", use_container_width=True)

    if run_mail and mail_domain:
        with st.spinner(f"Auditing DNS records for {mail_domain}..."):
            m_res = mail_checker.check_domain(mail_domain)

            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            with m_col1:
                st.metric("Security Score", f"{m_res['score']} / 100")
            with m_col2:
                r_label = m_res["rating"]
                st.metric("Spoof Posture", r_label)
            with m_col3:
                st.metric("Mail Provider", m_res.get("mx", {}).get("provider", "None"))
            with m_col4:
                st.metric("DMARC Policy", m_res.get("dmarc", {}).get("policy", "none").upper())

            st.markdown("---")
            c_mx, c_spf, c_dmarc = st.columns(3)

            with c_mx:
                st.markdown(f"**MX Exchangers ({m_res.get('mx', {}).get('count', 0)})**")
                mx_recs = m_res.get("mx", {}).get("records", [])
                if mx_recs:
                    for rec in mx_recs:
                        st.code(f"[{rec['priority']}] {rec['host']}", language="text")
                else:
                    st.caption("No MX records configured.")

            with c_spf:
                st.markdown(f"**SPF Record ({m_res.get('spf', {}).get('status', 'MISSING')})**")
                spf_val = m_res.get("spf", {}).get("record")
                if spf_val:
                    st.code(spf_val, language="text")
                    st.caption(f"Mechanism: {m_res.get('spf', {}).get('mechanism')}")
                else:
                    st.error("No SPF record found. Domain is vulnerable to spoofing!")

            with c_dmarc:
                st.markdown(f"**DMARC Policy ({m_res.get('dmarc', {}).get('policy', 'none').upper()})**")
                dmarc_val = m_res.get("dmarc", {}).get("record")
                if dmarc_val:
                    st.code(dmarc_val, language="text")
                    st.caption(m_res.get("dmarc", {}).get("details", ""))
                else:
                    st.error("No DMARC record found. Direct impersonation is possible!")

            if m_res.get("issues"):
                st.markdown("---")
                st.markdown("**Security Findings & Recommendations**")
                for issue in m_res["issues"]:
                    st.markdown(f"- ⚠️ {issue}")
            else:
                st.success("All email authentication protocols (MX, SPF, DMARC) are optimally configured!")

# ------------------------------------------
# TAB 2: LOCAL CACHE & HISTORY
# ------------------------------------------
with tab_cache:
    st.markdown("#### 💾 SQLite Cache Records")
    cache_stats = get_cache_stats()

    col_cs1, col_cs2, col_cs3 = st.columns([1, 1, 2])
    with col_cs1:
        st.metric("Active Cached IoCs", cache_stats["active"])
    with col_cs2:
        st.metric("Expired Records", cache_stats["expired"])
    with col_cs3:
        if st.button("🗑️ Purge Entire Cache", type="secondary"):
            cleared = clear_cache()
            st.success(f"Purged {cleared} records from SQLite cache.")
            st.rerun()

    cached_list = get_all_cached_iocs(limit=100)
    if cached_list:
        cdf = pd.DataFrame(cached_list)
        st.dataframe(cdf, use_container_width=True, hide_index=True)
    else:
        st.info("Cache is currently empty.")

    st.markdown("---")
    st.markdown("#### 📜 Scan Audit Log")
    history = get_scan_history(limit=15)
    if history:
        hdf = pd.DataFrame(history)
        st.dataframe(hdf, use_container_width=True, hide_index=True)
    else:
        st.caption("No scan history logged yet.")

# ------------------------------------------
# TAB 3: API HEALTH & DIAGNOSTICS
# ------------------------------------------
with tab_diagnostics:
    st.markdown("#### 📊 Threat Intelligence API Health & Rotation Status")
    st.markdown(
        """
        Slothery uses a **load-balanced key pool** for both VirusTotal and AbuseIPDB.
        When a key encounters rate limits (HTTP 429), it automatically rotates to the next healthy key in the pool.
        """
    )

    col_h1, col_h2 = st.columns([1, 1])

    with col_h1:
        st.markdown("##### 🛡️ VirusTotal v3 Key Pool")
        vt_client = VirusTotalClient(km)
        vt_keys = km.get_service_summary(SERVICE_VT)
        if not vt_keys:
            st.warning("No VirusTotal API keys found in pool. Add one via the sidebar.")
        else:
            for k in vt_keys:
                with st.container():
                    st.markdown(f"**Key:** `{k['key_masked']}` | Status: **{k['status']}**")
                    st.caption(f"Queries: {k['total_queries']} | Errors: {k['errors']} | Cooldown Remaining: {k['remaining_cooldown']}s")
                    if st.button(f"Test Key {k['key_masked']}", key=f"tst_vt_{k['key_raw']}"):
                        with st.spinner("Testing with VirusTotal..."):
                            ok, msg = vt_client.test_key(k["key_raw"])
                            if ok:
                                st.success(msg)
                            else:
                                st.error(msg)
                    st.markdown("---")

    with col_h2:
        st.markdown("##### 🚨 AbuseIPDB v2 Key Pool")
        abuse_client = AbuseIPDBClient(km)
        abuse_keys = km.get_service_summary(SERVICE_ABUSE)
        if not abuse_keys:
            st.warning("No AbuseIPDB API keys found in pool. Add one via the sidebar.")
        else:
            for k in abuse_keys:
                with st.container():
                    st.markdown(f"**Key:** `{k['key_masked']}` | Status: **{k['status']}**")
                    st.caption(f"Queries: {k['total_queries']} | Errors: {k['errors']} | Cooldown Remaining: {k['remaining_cooldown']}s")
                    if st.button(f"Test Key {k['key_masked']}", key=f"tst_abuse_{k['key_raw']}"):
                        with st.spinner("Testing with AbuseIPDB..."):
                            ok, msg = abuse_client.test_key(k["key_raw"])
                            if ok:
                                st.success(msg)
                            else:
                                st.error(msg)
                    st.markdown("---")

    st.markdown("---")
    st.markdown("##### 🔗 Getting Free API Keys")
    st.markdown(
        """
        - **VirusTotal Community (Free)**: Sign up at [virustotal.com](https://www.virustotal.com) → Profile → API Key. Limit: 4 requests/min, 500 requests/day.
        - **AbuseIPDB (Free)**: Sign up at [abuseipdb.com](https://www.abuseipdb.com) → Account → API. Limit: 1,000 checks/day.
        """
    )
