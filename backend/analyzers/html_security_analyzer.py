"""
HTML Security Analyzer.
Analyzes insecure form actions (plaintext HTTP), insecure external scripts (HTTP),
dangerous inline JavaScript execution, and reverse tabnabbing (target=_blank without noopener).
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_html(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("<!--"):
            continue

        # 1. Insecure Form Action over Plaintext HTTP
        if re.search(r"""<form\b[^>]*\baction=["']http://""", line, re.IGNORECASE):
            findings.append(
                build_finding(
                    vuln_type="Insecure HTML Form",
                    severity="HIGH",
                    line=idx,
                    description="HTML form configured with unencrypted HTTP action URL.",
                    why="Submitting credentials or personal data over plaintext HTTP exposes transmission to man-in-the-middle interception.",
                    impact="Cleartext credential theft and session eavesdropping.",
                    fix="Use HTTPS for all form action targets: action=\"https://...\".",
                    confidence=94,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="HTML Form Action Inspection",
                )
            )

        # 2. Insecure External Script over HTTP
        if re.search(r"""<script\b[^>]*\bsrc=["']http://""", line, re.IGNORECASE):
            findings.append(
                build_finding(
                    vuln_type="Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    line=idx,
                    description="External script loaded over unencrypted HTTP protocol.",
                    why="Loading scripts over HTTP enables network attackers to inject malicious JavaScript into the webpage via man-in-the-middle tampering.",
                    impact="Client-side script execution and complete session compromise.",
                    fix="Serve all external scripts over HTTPS with Subresource Integrity (SRI) hashes.",
                    confidence=95,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="HTML Script Source Protocol Verification",
                )
            )

        # 3. Dangerous Inline Event with eval / document.write
        inline_eval = re.search(r"""\bon\w+\s*=\s*["'][^"']*(?:eval\s*\(|document\.write\s*\()""", line, re.IGNORECASE)
        if inline_eval:
            findings.append(
                build_finding(
                    vuln_type="Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    line=idx,
                    description="Dangerous DOM manipulation function (eval/document.write) in inline HTML event handler.",
                    why="Executing dynamic evaluation in inline event attributes creates high-risk DOM XSS vectors and violates CSP policies.",
                    impact="Arbitrary script execution within user session.",
                    fix="Move logic to separate external JavaScript files using addEventListener without eval or document.write.",
                    confidence=93,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Inline Event Attribute Analysis",
                )
            )

        # 4. Reverse Tabnabbing: target="_blank" without rel="noopener" on external link
        if re.search(r"""<a\b[^>]*\btarget=["']_blank["'][^>]*\bhref=["']https?://""", line, re.IGNORECASE):
            if not re.search(r"""\brel=["'][^"']*noopener""", line, re.IGNORECASE):
                findings.append(
                    build_finding(
                        vuln_type="Cross-Site Scripting (XSS)",
                        severity="LOW",
                        line=idx,
                        description="External link with target=\"_blank\" missing rel=\"noopener noreferrer\".",
                        why="Without rel=\"noopener\", the opened page can access the opener page via window.opener and redirect it to a phishing site (reverse tabnabbing).",
                        impact="Potential phishing of the parent tab.",
                        fix="Add rel=\"noopener noreferrer\" to all external target=\"_blank\" anchors.",
                        confidence=90,
                        exploitability="LOW",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="HTML Anchor Security Attribute Check",
                    )
                )

    return findings
