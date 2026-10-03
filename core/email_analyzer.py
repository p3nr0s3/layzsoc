"""Phishing Email and RFC 822 Header Analyzer for Slothery."""

import re
import email
import hashlib
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional
from core.parser import parse_raw_text, defang_string, refang_string

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".hta", ".ps1",
    ".iso", ".img", ".dll", ".pif", ".cpl", ".wsf", ".jar",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

POPULAR_BRANDS = [
    "paypal", "microsoft", "office365", "google", "apple", "netflix",
    "amazon", "facebook", "bank", "chase", "wells fargo", "docusign",
    "dropbox", "security team", "it helpdesk", "ceo", "payroll", "invoice"
]


def extract_email_address(text: str) -> str:
    """Extracts raw email address from header field like 'John <john@example.com>'."""
    if not text:
        return ""
    match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text)
    return match.group(0).lower() if match else text.strip().lower()


def get_domain_from_email(addr: str) -> str:
    """Extracts domain from email address."""
    clean = extract_email_address(addr)
    if "@" in clean:
        return clean.split("@")[-1]
    return ""


class EmailAnalyzer:
    """Parses and evaluates phishing indicators from email headers and MIME bodies."""

    def analyze(self, raw_input: bytes, filename: str = "email.eml") -> Dict[str, Any]:
        """Performs full phishing and header analysis."""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_input)
        except Exception:
            # Fallback for plain header text
            msg = email.message_from_bytes(raw_input)

        subject = str(msg.get("Subject", "(No Subject)"))
        date = str(msg.get("Date", "Unknown"))
        msg_id = str(msg.get("Message-ID", "Unknown"))
        from_hdr = str(msg.get("From", ""))
        to_hdr = str(msg.get("To", ""))
        reply_to = str(msg.get("Reply-To", ""))
        return_path = str(msg.get("Return-Path", ""))

        from_addr = extract_email_address(from_hdr)
        from_domain = get_domain_from_email(from_hdr)
        reply_addr = extract_email_address(reply_to)
        reply_domain = get_domain_from_email(reply_to)
        return_addr = extract_email_address(return_path)
        return_domain = get_domain_from_email(return_path)

        # 1. Authentication Results
        auth_results = self._parse_authentication(msg)

        # 2. Hop Trace / Received Headers
        hops = self._parse_received_hops(msg)

        # 3. Body & Link Extraction
        body_text, links = self._extract_body_and_links(msg)

        # 4. Attachment Extraction & Hashes
        attachments = self._extract_attachments(msg)

        # 5. Phishing Risk Assessment
        risk_score, risk_verdict, alerts = self._evaluate_phishing_risk(
            from_hdr=from_hdr,
            from_domain=from_domain,
            reply_domain=reply_domain,
            return_domain=return_domain,
            auth=auth_results,
            links=links,
            attachments=attachments,
        )

        return {
            "filename": filename,
            "subject": subject,
            "date": date,
            "message_id": msg_id,
            "headers": {
                "from": from_hdr,
                "from_address": from_addr,
                "from_domain": from_domain,
                "to": to_hdr,
                "reply_to": reply_to or None,
                "reply_address": reply_addr or None,
                "return_path": return_path or None,
                "return_address": return_addr or None,
            },
            "authentication": auth_results,
            "hops": hops,
            "links": links,
            "attachments": attachments,
            "risk_score": risk_score,  # 0 to 100
            "risk_verdict": risk_verdict,  # 'PHISHING / MALICIOUS', 'SUSPICIOUS', 'CLEAN'
            "alerts": alerts,
            "body_snippet": body_text[:600] if body_text else "",
        }

    def _parse_authentication(self, msg) -> Dict[str, str]:
        auth_str = str(msg.get("Authentication-Results", "")) + " " + str(msg.get("Received-SPF", ""))
        auth_lower = auth_str.lower()

        spf = "unknown"
        if "spf=pass" in auth_lower or "pass (" in auth_lower:
            spf = "PASS"
        elif "spf=fail" in auth_lower or "softfail" in auth_lower:
            spf = "FAIL"
        elif "spf=none" in auth_lower:
            spf = "NONE"

        dkim = "unknown"
        if "dkim=pass" in auth_lower:
            dkim = "PASS"
        elif "dkim=fail" in auth_lower:
            dkim = "FAIL"
        elif "dkim=none" in auth_lower:
            dkim = "NONE"

        dmarc = "unknown"
        if "dmarc=pass" in auth_lower:
            dmarc = "PASS"
        elif "dmarc=fail" in auth_lower:
            dmarc = "FAIL"
        elif "dmarc=none" in auth_lower:
            dmarc = "NONE"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "raw_auth": auth_str[:300] if auth_str.strip() else "None provided in headers",
        }

    def _parse_received_hops(self, msg) -> List[Dict[str, str]]:
        hops = []
        received_list = msg.get_all("Received") or []
        for r in received_list:
            r_str = str(r).replace("\n", " ").replace("\t", " ")
            # Find originating/relay IP
            ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", r_str)
            from_match = re.search(r"from\s+([^\s]+)", r_str, re.IGNORECASE)
            by_match = re.search(r"by\s+([^\s]+)", r_str, re.IGNORECASE)

            hops.append({
                "from": from_match.group(1) if from_match else "Unknown",
                "by": by_match.group(1) if by_match else "Unknown",
                "ip": ip_match.group(1) if ip_match else None,
                "raw": r_str[:120],
            })
        return hops

    def _extract_body_and_links(self, msg) -> tuple[str, List[Dict[str, str]]]:
        body = ""
        links = []
        seen_links = set()

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = str(part.get("Content-Disposition", ""))
                if "attachment" not in cdisp:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += " " + payload.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="ignore")
            except Exception:
                body = str(msg.get_payload())

        # Extract URLs
        raw_iocs = parse_raw_text(body)
        for i in raw_iocs:
            if i.ioc_type == "url" and i.value not in seen_links:
                seen_links.add(i.value)
                links.append({
                    "url": i.value,
                    "defanged": refang_string(i.value, "url"),
                })

        return body.strip(), links

    def _extract_attachments(self, msg) -> List[Dict[str, Any]]:
        attachments = []
        for part in msg.walk():
            cdisp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if "attachment" in cdisp or filename:
                fname = filename or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""

                size_bytes = len(payload)
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()

                is_dangerous = any(fname.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)

                attachments.append({
                    "filename": fname,
                    "content_type": part.get_content_type(),
                    "size_bytes": size_bytes,
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "is_dangerous": is_dangerous,
                })

        return attachments

    def _evaluate_phishing_risk(
        self,
        from_hdr: str,
        from_domain: str,
        reply_domain: str,
        return_domain: str,
        auth: Dict[str, str],
        links: List[Dict[str, str]],
        attachments: List[Dict[str, Any]],
    ) -> tuple[int, str, List[str]]:
        score = 0
        alerts = []

        # 1. Display Name Spoofing
        from_hdr_lower = from_hdr.lower()
        for brand in POPULAR_BRANDS:
            if brand in from_hdr_lower and brand not in from_domain:
                score += 35
                alerts.append(f"Display Name Impersonation: Name mentions '{brand.title()}' but sender domain is '{from_domain}'.")
                break

        # 2. Reply-To Mismatch
        if reply_domain and from_domain and reply_domain != from_domain:
            score += 25
            alerts.append(f"Reply-To Mismatch: Replies are redirected to '@{reply_domain}' instead of '@{from_domain}'.")

        # 3. Return-Path Mismatch
        if return_domain and from_domain and return_domain != from_domain:
            score += 15
            alerts.append(f"Envelope Sender Mismatch: Return-Path is '@{return_domain}'.")

        # 4. Authentication Failures
        if auth.get("dmarc") == "FAIL":
            score += 30
            alerts.append("DMARC Authentication FAILED. Sender domain policy was violated.")
        if auth.get("spf") == "FAIL":
            score += 20
            alerts.append("SPF Authentication FAILED. Email originated from unauthorized IP.")

        # 5. Dangerous Attachments
        dangerous_att = [a["filename"] for a in attachments if a.get("is_dangerous")]
        if dangerous_att:
            score += 40
            alerts.append(f"Dangerous Executable/Macro Attachment(s): {', '.join(dangerous_att)}")

        # 6. Suspicious Links
        ip_links = [l["url"] for l in links if re.search(r"https?://\d{1,3}\.\d{1,3}", l["url"])]
        if ip_links:
            score += 25
            alerts.append(f"Direct IP-based URL detected in body: {ip_links[0]}")

        # Verdict assignment
        score = min(100, score)
        if score >= 60:
            verdict = "PHISHING / MALICIOUS"
        elif score >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE / LOW RISK"

        return score, verdict, alerts
