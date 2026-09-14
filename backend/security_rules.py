"""
Security Rules Coordinator.
Coordinates static vulnerability scans across 15 supported languages,
dispatching to modular analyzers while preserving backward-compatible helper functions.
"""

import re
from typing import List, Dict, Any, Optional

from python_taint_analyzer import analyze_python_sql_injection
from command_injection_analyzer import analyze_python_command_injection
from xss_analyzer import analyze_python_xss
from hardcoded_secret_analyzer import analyze_python_hardcoded_secrets
from buffer_overflow_analyzer import analyze_c_cpp_buffer_overflow

from analyzers import (
    analyze_python,
    analyze_javascript,
    analyze_java,
    analyze_c_cpp,
    analyze_csharp,
    analyze_php,
    analyze_go,
    analyze_ruby,
    analyze_rust,
    analyze_kotlin,
    analyze_swift,
    analyze_sql,
    analyze_html,
)


# =========================================================
# BACKWARD COMPATIBLE LEGACY HELPERS
# =========================================================

def create_finding(
    vulnerability_type,
    severity,
    line,
    description,
    why,
    impact,
    fix,
    confidence=85,
):
    return {
        "type": vulnerability_type,
        "severity": severity,
        "line": line,
        "primary_line": line,
        "affected_lines": [line] if line else [],
        "description": description,
        "why": why,
        "impact": impact,
        "fix": fix,
        "confidence": confidence,
        "detection_source": "ENGINE",
        "evidence_level": "HIGH_CONFIDENCE",
    }


def detect_sql_injection(code):
    findings = []
    lines = code.split("\n")
    sql_words = r"(SELECT|INSERT|UPDATE|DELETE|DROP)"

    for number, line in enumerate(lines, start=1):
        has_sql = re.search(sql_words, line, re.IGNORECASE)
        unsafe_building = (
            "+" in line
            or "f\"" in line
            or "f'" in line
            or "${" in line
            or ".format(" in line
        )
        if has_sql and unsafe_building:
            findings.append(
                create_finding(
                    "SQL Injection",
                    "HIGH",
                    number,
                    "SQL query may contain dynamically inserted user-controlled data.",
                    "User input appears to be directly combined with an SQL query.",
                    "An attacker may modify the intended database query.",
                    "Use parameterized queries or prepared statements.",
                    90,
                )
            )
    return findings


def detect_xss(code):
    findings = []
    lines = code.split("\n")
    patterns = [
        r"\.innerHTML\s*=",
        r"document\.write\s*\(",
        r"dangerouslySetInnerHTML",
    ]

    for number, line in enumerate(lines, start=1):
        for pattern in patterns:
            if re.search(pattern, line):
                findings.append(
                    create_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        number,
                        "Potential unsafe HTML rendering detected.",
                        "Untrusted data may be inserted directly into webpage content.",
                        "Malicious script content could execute inside the user's browser.",
                        "Escape or sanitize untrusted content before rendering it.",
                        88,
                    )
                )
                break
    return findings


def detect_hardcoded_secret(code):
    findings = []
    lines = code.split("\n")
    pattern = re.compile(
        r"""(?ix)
        \b(
            password
            |passwd
            |pwd
            |api[_-]?key
            |secret
            |client[_-]?secret
            |access[_-]?token
            |auth[_-]?token
            |admin[_-]?token
            |jwt[_-]?secret
            |private[_-]?key
        )\b
        \s*[:=]\s*
        ["'][^"']{8,}["']
        """
    )

    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            findings.append(
                create_finding(
                    "Hardcoded Secret",
                    "HIGH",
                    number,
                    "A credential or secret appears to be hardcoded.",
                    "Sensitive credentials should not be stored directly in source code.",
                    "The credential may become exposed through source-code access or repositories.",
                    "Move secrets to environment variables or a secure secret manager.",
                    90,
                )
            )
    return findings


def detect_command_injection(code):
    findings = []
    lines = code.split("\n")
    dangerous_patterns = [
        r"os\.system\s*\(",
        r"Runtime\.getRuntime\(\)\.exec\s*\(",
        r"child_process\.exec\s*\(",
        r"exec\s*\(",
        r"popen\s*\(",
    ]

    for number, line in enumerate(lines, start=1):
        for pattern in dangerous_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(
                    create_finding(
                        "Command Injection",
                        "CRITICAL",
                        number,
                        "Potential execution of an operating-system command was detected.",
                        "External or user-controlled input may reach a command execution function.",
                        "An attacker may execute unintended operating-system commands.",
                        "Avoid shell execution with user input and use safe argument-based APIs.",
                        92,
                    )
                )
                break
        if "subprocess" in line and "shell=True" in line.replace(" ", ""):
            findings.append(
                create_finding(
                    "Command Injection",
                    "CRITICAL",
                    number,
                    "subprocess execution with shell=True was detected.",
                    "Shell execution increases risk when command data contains external input.",
                    "An attacker may manipulate the executed command.",
                    "Avoid shell=True and pass command arguments as a list.",
                    94,
                )
            )
    return findings


def detect_buffer_overflow(code):
    findings = []
    lines = code.split("\n")
    char_buffers = {}
    buffer_pattern = re.compile(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]")

    for number, line in enumerate(lines, start=1):
        match = buffer_pattern.search(line)
        if match:
            variable = match.group(1)
            char_buffers[variable] = number

    for number, line in enumerate(lines, start=1):
        if "gets(" in line:
            findings.append(
                create_finding(
                    "Buffer Overflow Risk",
                    "CRITICAL",
                    number,
                    "gets() detected with unbounded input.",
                    "gets does not perform buffer bound checks.",
                    "Stack buffer overflow.",
                    "Use fgets().",
                    98,
                )
            )
    return findings


# Backward-compatible bridge functions
def get_advanced_python_sql_findings(code):
    res = analyze_python_sql_injection(code)
    return res.get("findings") if res and isinstance(res, dict) else None


def get_advanced_python_xss_findings(code):
    res = analyze_python_xss(code)
    return res.get("findings") if res and isinstance(res, dict) else None


def get_advanced_python_secret_findings(code):
    res = analyze_python_hardcoded_secrets(code)
    return res.get("findings") if res and isinstance(res, dict) else None


def get_advanced_python_command_findings(code):
    res = analyze_python_command_injection(code)
    return res.get("findings") if res and isinstance(res, dict) else None


def get_advanced_c_cpp_buffer_findings(code):
    res = analyze_c_cpp_buffer_overflow(code)
    return res.get("findings") if res and isinstance(res, dict) else None


# =========================================================
# MAIN SECURITY SCANNER COORDINATOR
# =========================================================

def scan_security(code: str, language: str = "Unknown") -> List[Dict[str, Any]]:
    """
    Scans submitted source code using the appropriate modular language analyzer.
    Preserves all existing AST and buffer tracking evidence.
    """
    if not code or not code.strip():
        return []

    norm_lang = str(language).lower().strip()
    print(f"[SECURITY] Starting vulnerability scan for: {language}")

    findings: List[Dict[str, Any]] = []

    # Route to specialized modular analyzers
    if norm_lang in ("python", "py"):
        findings = analyze_python(code)

    elif norm_lang in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
        findings = analyze_javascript(code)

    elif norm_lang in ("java",):
        findings = analyze_java(code)

    elif norm_lang in ("c", "c++", "cpp", "cc", "cxx", "h", "hpp"):
        findings = analyze_c_cpp(code)

    elif norm_lang in ("c#", "csharp", "cs"):
        findings = analyze_csharp(code)

    elif norm_lang in ("php",):
        findings = analyze_php(code)

    elif norm_lang in ("go", "golang"):
        findings = analyze_go(code)

    elif norm_lang in ("ruby", "rb"):
        findings = analyze_ruby(code)

    elif norm_lang in ("rust", "rs"):
        findings = analyze_rust(code)

    elif norm_lang in ("kotlin", "kt", "kts"):
        findings = analyze_kotlin(code)

    elif norm_lang in ("swift",):
        findings = analyze_swift(code)

    elif norm_lang in ("sql",):
        findings = analyze_sql(code)

    elif norm_lang in ("html", "htm"):
        findings = analyze_html(code)

    else:
        # Fallback for unknown language: run non-language specific heuristics
        findings.extend(detect_sql_injection(code))
        findings.extend(detect_xss(code))
        findings.extend(detect_hardcoded_secret(code))
        findings.extend(detect_command_injection(code))
        findings.extend(detect_buffer_overflow(code))

    # Sequential finding IDs
    for index, finding in enumerate(findings, start=1):
        finding["id"] = index

    print(f"[SECURITY] Scan complete - {len(findings)} issue(s) found.")
    return findings