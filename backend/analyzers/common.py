"""
Common utilities, schemas, and helpers for language-specific security analyzers.
"""

from typing import Dict, Any, List, Optional


CWE_OWASP_MAP = {
    "SQL Injection": {
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
    },
    "Command Injection": {
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
    },
    "Cross-Site Scripting (XSS)": {
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
    },
    "Path Traversal": {
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
    },
    "Hardcoded Secret": {
        "cwe": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
    },
    "Buffer Overflow Risk": {
        "cwe": "CWE-120",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
    },
    "Server-Side Request Forgery (SSRF)": {
        "cwe": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
    },
    "Insecure Deserialization": {
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
    },
    "XML External Entity (XXE)": {
        "cwe": "CWE-611",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Code Injection": {
        "cwe": "CWE-94",
        "owasp": "A03:2021-Injection",
    },
    "Template Injection": {
        "cwe": "CWE-1336",
        "owasp": "A03:2021-Injection",
    },
    "Weak Cryptography": {
        "cwe": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
    },
    "Insecure Randomness": {
        "cwe": "CWE-338",
        "owasp": "A02:2021-Cryptographic Failures",
    },
    "Prototype Pollution": {
        "cwe": "CWE-1321",
        "owasp": "A03:2021-Injection",
    },
    "Format String Vulnerability": {
        "cwe": "CWE-134",
        "owasp": "A03:2021-Injection",
    },
    "Memory Safety Risk": {
        "cwe": "CWE-416",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
    },
    "File Inclusion": {
        "cwe": "CWE-98",
        "owasp": "A03:2021-Injection",
    },
    "Sensitive Data Exposure": {
        "cwe": "CWE-200",
        "owasp": "A04:2021-Insecure Design",
    },
    "Privilege Escalation Risk": {
        "cwe": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
    },
    "Insecure HTML Form": {
        "cwe": "CWE-319",
        "owasp": "A02:2021-Cryptographic Failures",
    },
}


def build_finding(
    vuln_type: str,
    severity: str,
    line: int,
    description: str,
    why: str,
    impact: str,
    fix: str,
    confidence: int = 85,
    exploitability: str = "MEDIUM",
    affected_lines: Optional[List[int]] = None,
    source: Optional[Dict[str, Any]] = None,
    sink: Optional[Dict[str, Any]] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
    evidence_level: str = "HIGH_CONFIDENCE",
    analysis_method: str = "Language-Aware Static Analysis",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Constructs a normalized vulnerability finding adhering to the system schema.
    """
    primary_line = int(line) if line else 0
    aff_lines = list(affected_lines) if affected_lines else ([primary_line] if primary_line > 0 else [])
    
    mapping = CWE_OWASP_MAP.get(vuln_type, {})
    cwe = mapping.get("cwe", "CWE-Other")
    owasp = mapping.get("owasp", "Security Finding")

    finding: Dict[str, Any] = {
        "type": vuln_type,
        "severity": severity.upper(),
        "confidence": confidence,
        "exploitability": exploitability.upper(),
        "cwe": cwe,
        "owasp": owasp,
        "line": primary_line,
        "primary_line": primary_line,
        "affected_lines": sorted(set(aff_lines)),
        "description": description,
        "why": why,
        "impact": impact,
        "fix": fix,
        "source": source,
        "sink": sink,
        "evidence": evidence or [],
        "location": {
            "start_line": min(aff_lines) if aff_lines else primary_line,
            "end_line": max(aff_lines) if aff_lines else primary_line,
        },
        "evidence_level": evidence_level,
        "analysis_method": analysis_method,
        "detection_source": "ENGINE",
        "severity_reason": f"Deterministic engine assessed {severity.upper()} based on {evidence_level}.",
    }

    if extra:
        finding.update(extra)

    return finding
