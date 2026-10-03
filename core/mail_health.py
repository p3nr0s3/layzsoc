"""Mail Health and Domain Spoofing Posture Checker for Slothery."""

import re
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.exception


class MailHealthChecker:
    """Evaluates MX, SPF, and DMARC configurations to assess email spoofability."""

    def __init__(self, timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Performs full Mail Health and anti-spoofing audit for a domain."""
        dom = domain.lower().strip()
        # Clean protocol or path if passed accidentally
        if "://" in dom:
            dom = dom.split("://")[1].split("/")[0]
        dom = dom.split("/")[0].split(":")[0]

        mx_res = self._check_mx(dom)
        spf_res = self._check_spf(dom)
        dmarc_res = self._check_dmarc(dom)

        score, rating, verdict, issues = self._calculate_health_score(mx_res, spf_res, dmarc_res)

        return {
            "domain": dom,
            "score": score,  # 0 to 100
            "rating": rating,  # 'PROTECTED', 'PARTIALLY_PROTECTED', 'VULNERABLE'
            "verdict": verdict,
            "mx": mx_res,
            "spf": spf_res,
            "dmarc": dmarc_res,
            "issues": issues,
        }

    def _check_mx(self, domain: str) -> Dict[str, Any]:
        try:
            answers = self.resolver.resolve(domain, "MX")
            records = []
            for r in answers:
                records.append({
                    "priority": r.preference,
                    "host": str(r.exchange).rstrip("."),
                })
            records.sort(key=lambda x: x["priority"])

            provider = "Custom / Private"
            hosts_str = " ".join(r["host"].lower() for r in records)
            if "google" in hosts_str or "aspmx" in hosts_str:
                provider = "Google Workspace"
            elif "outlook" in hosts_str or "microsoft" in hosts_str:
                provider = "Microsoft 365"
            elif "zoho" in hosts_str:
                provider = "Zoho Mail"
            elif "proton" in hosts_str:
                provider = "Proton Mail"
            elif "pphosted" in hosts_str or "proofpoint" in hosts_str:
                provider = "Proofpoint Security Gateway"
            elif "mimecast" in hosts_str:
                provider = "Mimecast Security Gateway"

            return {
                "has_mx": True,
                "provider": provider,
                "records": records,
                "count": len(records),
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"has_mx": False, "provider": "None", "records": [], "count": 0}
        except Exception as e:
            return {"has_mx": False, "provider": "Error", "records": [], "error": str(e), "count": 0}

    def _check_spf(self, domain: str) -> Dict[str, Any]:
        try:
            answers = self.resolver.resolve(domain, "TXT")
            spf_records = []
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)

            if not spf_records:
                return {
                    "has_spf": False,
                    "record": None,
                    "status": "MISSING",
                    "mechanism": "None",
                    "details": "No SPF TXT record found. Attackers can forge mail from this domain.",
                }

            record = spf_records[0]
            # Check mechanism (+all, -all, ~all, ?all)
            mechanism = "Unknown"
            status = "ACCEPTABLE"
            if "-all" in record:
                mechanism = "HardFail (-all)"
                status = "STRICT"
            elif "~all" in record:
                mechanism = "SoftFail (~all)"
                status = "MODERATE"
            elif "?all" in record:
                mechanism = "Neutral (?all)"
                status = "WEAK"
            elif "+all" in record:
                mechanism = "Pass (+all)"
                status = "CRITICAL_RISK"

            return {
                "has_spf": True,
                "record": record,
                "status": status,
                "mechanism": mechanism,
                "count": len(spf_records),
                "is_multiple": len(spf_records) > 1,
            }
        except Exception:
            return {
                "has_spf": False,
                "record": None,
                "status": "MISSING",
                "mechanism": "None",
                "details": "No SPF record found or query failed.",
            }

    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        dmarc_host = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_host, "TXT")
            dmarc_records = []
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)

            if not dmarc_records:
                return {
                    "has_dmarc": False,
                    "record": None,
                    "policy": "none",
                    "status": "MISSING",
                    "details": "No DMARC record found. Domain is vulnerable to direct sender spoofing.",
                }

            record = dmarc_records[0]
            policy_match = re.search(r"p\s*=\s*([a-zA-Z]+)", record)
            policy = policy_match.group(1).lower() if policy_match else "unknown"

            rua_match = re.search(r"rua\s*=\s*mailto:([^\s;]+)", record)
            reporting_email = rua_match.group(1) if rua_match else None

            pct_match = re.search(r"pct\s*=\s*(\d+)", record)
            pct = int(pct_match.group(1)) if pct_match else 100

            status = "VULNERABLE"
            if policy == "reject":
                status = "STRICT_PROTECTED"
            elif policy == "quarantine":
                status = "PROTECTED"
            elif policy == "none":
                status = "MONITORING_ONLY"

            return {
                "has_dmarc": True,
                "record": record,
                "policy": policy,
                "status": status,
                "reporting_email": reporting_email,
                "pct": pct,
                "details": f"Policy set to {policy.upper()} ({pct}% enforcement)",
            }
        except Exception:
            return {
                "has_dmarc": False,
                "record": None,
                "policy": "none",
                "status": "MISSING",
                "details": "No DMARC record configured.",
            }

    def _calculate_health_score(
        self,
        mx: Dict[str, Any],
        spf: Dict[str, Any],
        dmarc: Dict[str, Any],
    ) -> Tuple[int, str, str, List[str]]:
        score = 0
        issues = []

        # MX component (20 pts)
        if mx.get("has_mx"):
            score += 20
        else:
            issues.append("No active MX records (Domain cannot receive emails).")

        # SPF component (35 pts)
        if spf.get("has_spf"):
            if spf.get("status") == "STRICT":
                score += 35
            elif spf.get("status") == "MODERATE":
                score += 28
                issues.append("SPF uses SoftFail (~all). Recommended: HardFail (-all).")
            elif spf.get("status") == "WEAK":
                score += 15
                issues.append("SPF uses Neutral (?all). Spoofed emails will not be blocked.")
            elif spf.get("status") == "CRITICAL_RISK":
                score += 0
                issues.append("CRITICAL: SPF uses +all, allowing any IP to send mail on your behalf!")
            if spf.get("is_multiple"):
                issues.append("Multiple SPF records detected. This causes SPF PermError!")
                score = max(0, score - 15)
        else:
            issues.append("Missing SPF record. Anyone can forge emails from this domain.")

        # DMARC component (45 pts)
        if dmarc.get("has_dmarc"):
            pol = dmarc.get("policy")
            if pol == "reject":
                score += 45
            elif pol == "quarantine":
                score += 35
                issues.append("DMARC policy is quarantine. Consider upgrading to p=reject.")
            elif pol == "none":
                score += 15
                issues.append("DMARC policy is p=none (monitoring only). Direct spoofing is NOT blocked.")
        else:
            issues.append("Missing DMARC record. Highly susceptible to brand impersonation and phishing.")

        # Rating categorization
        if score >= 80:
            rating = "PROTECTED"
            verdict = "Strong Anti-Spoofing Posture"
        elif score >= 50:
            rating = "PARTIALLY_PROTECTED"
            verdict = "Partially Protected (Spoofing Possible)"
        else:
            rating = "VULNERABLE"
            verdict = "Vulnerable to Email Spoofing & Phishing"

        return score, rating, verdict, issues
