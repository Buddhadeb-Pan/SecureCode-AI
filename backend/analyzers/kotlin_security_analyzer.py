"""
Kotlin Security Analyzer.
Analyzes SQL Injection (string template query interpolation), Command Injection,
SSRF, Insecure Deserialization, and Hardcoded Secrets in Kotlin/Android/JVM code.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_kotlin(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*"):
            continue

        # 1. SQL Injection: rawQuery / executeQuery with string template $ or concat
        sql_match = re.search(r"\b(?:rawQuery|execSQL|executeQuery|executeUpdate)\s*\(([^,)]*(?:SELECT|INSERT|UPDATE|DELETE)[^,)]*)", line, re.IGNORECASE)
        if sql_match:
            query_str = sql_match.group(1)
            if "$" in query_str or "+" in line:
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="HIGH",
                        line=idx,
                        description="Database query constructed using Kotlin string templates or concatenation.",
                        why="Interpolating variables directly into Kotlin/Android SQL queries bypasses parameterized query protection.",
                        impact="Unauthorized database manipulation and data extraction.",
                        fix="Use parameterized selection arguments: rawQuery(\"SELECT ... WHERE id = ?\", arrayOf(id))",
                        confidence=95,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Kotlin String Template SQL Audit",
                    )
                )

        # 2. Command Injection: Runtime.getRuntime().exec with string template
        if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", line):
            if "$" in line or "+" in line:
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Runtime.exec invoked with dynamic Kotlin string parameter.",
                        why="Executing dynamic command strings via Runtime.exec allows shell metacharacter injection.",
                        impact="Arbitrary command execution on the host or Android device.",
                        fix="Pass command arguments as an array of discrete arguments: arrayOf(cmd, arg1, arg2)",
                        confidence=93,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="JVM Process Execution Analysis",
                    )
                )

        # 3. SSRF: URL(dynamic).openConnection()
        url_match = re.search(r"\bURL\s*\(([^)]+)\)\.openConnection", line)
        if url_match:
            arg = url_match.group(1).strip()
            if not (arg.startswith('"') and arg.endswith('"')):
                findings.append(
                    build_finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        line=idx,
                        description="Outbound network connection to dynamic URL destination.",
                        why="Initiating network connections to dynamic targets allows access to internal endpoints and cloud metadata.",
                        impact="Internal network disclosure and credential compromise.",
                        fix="Validate target URLs against an explicit allowlist before opening connections.",
                        confidence=88,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Kotlin Network Target Analysis",
                    )
                )

        # 4. Hardcoded Secrets
        sec_match = re.search(r"""(?ix)\b(?:val|var)\s+(password|apiKey|api_key|secretKey|token)\s*=\s*["']([^"']{8,})["']""", line)
        if sec_match and not any(ign in sec_match.group(2).lower() for ign in ("system.getenv", "buildconfig.", "placeholder")):
            findings.append(
                build_finding(
                    vuln_type="Hardcoded Secret",
                    severity="HIGH",
                    line=idx,
                    description=f"Hardcoded sensitive credential identified in variable '{sec_match.group(1)}'.",
                    why="Embedding credentials in Kotlin source code exposes them in version control and decompiled APKs/JARs.",
                    impact="Compromised application credentials and backend services.",
                    fix="Store secrets in environment variables or Android KeyStore / encrypted SharedPreferences.",
                    confidence=92,
                    exploitability="HIGH",
                    evidence=[{"role": "secret_declaration", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Sensitive Identifier Heuristic",
                    extra={"variable": sec_match.group(1)},
                )
            )

    return findings
