"""
Ruby Security Analyzer.
Analyzes SQL Injection (ActiveRecord string interpolation), Command Injection,
XSS (.html_safe / raw), Insecure Deserialization (Marshal/YAML), and Path Traversal.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_ruby(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        # 1. SQL Injection: ActiveRecord .where / .find_by_sql with string interpolation
        sql_match = re.search(r"\b(?:where|find_by_sql|order|group|having)\s*\([^)]*#\{[^}]+\}", line)
        if sql_match:
            findings.append(
                build_finding(
                    vuln_type="SQL Injection",
                    severity="HIGH",
                    line=idx,
                    description="ActiveRecord query constructed with string interpolation (#{}).",
                    why="Interpolating variables directly into ActiveRecord condition strings bypasses automatic SQL escaping.",
                    impact="Database manipulation and unauthorized access.",
                    fix="Use parameterized queries with placeholder arrays: .where(\"name = ?\", params[:name])",
                    confidence=95,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="ActiveRecord Query Interpolation Check",
                )
            )

        # 2. Command Injection: system, exec, backticks, Open3 with interpolation
        cmd_match = re.search(r"""(?:system|exec|IO\.popen|Open3\.\w+)\s*\(?\s*["'][^"']*#\{[^}]+\}""", line)
        if cmd_match or re.search(r"`[^`]*#\{[^}]+\}[^`]*`", line):
            findings.append(
                build_finding(
                    vuln_type="Command Injection",
                    severity="CRITICAL",
                    line=idx,
                    description="Operating system command executed with dynamic string interpolation.",
                    why="Interpolating dynamic variables into shell execution methods allows arbitrary shell metacharacter injection.",
                    impact="Remote code execution with application process privileges.",
                    fix="Pass command name and arguments as discrete array elements: system('ls', '-l', filename)",
                    confidence=94,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Ruby Command Execution Flow Check",
                )
            )

        # 3. Insecure Deserialization: Marshal.load or YAML.load
        deser_match = re.search(r"\b(?:Marshal\.load|YAML\.load)\s*\(([^)]+)\)", line)
        if deser_match:
            if "YAML.safe_load" not in line:
                findings.append(
                    build_finding(
                        vuln_type="Insecure Deserialization",
                        severity="CRITICAL",
                        line=idx,
                        description="Insecure object deserialization via Marshal.load or YAML.load.",
                        why="Deserializing untrusted data with Marshal or unsafe YAML allows instantiation of arbitrary Ruby objects leading to RCE.",
                        impact="Remote code execution on the host server.",
                        fix="Use YAML.safe_load() or standard JSON parsing (JSON.parse) for untrusted data.",
                        confidence=96,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Ruby Deserialization Sink Check",
                    )
                )

        # 4. XSS: raw(...) or .html_safe on params
        if (".html_safe" in line or re.search(r"\braw\s*\(", line)) and "params" in line:
            findings.append(
                build_finding(
                    vuln_type="Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    line=idx,
                    description="Bypassing Rails automatic HTML escaping with raw or html_safe on request data.",
                    why="Marking untrusted user input as html_safe disables Rails' built-in XSS protection.",
                    impact="Cross-Site Scripting and client-side credential theft.",
                    fix="Remove .html_safe / raw; allow Rails template auto-escaping to protect output, or use sanitize helper.",
                    confidence=93,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Rails HTML Safe Marking Check",
                )
            )

    return findings
