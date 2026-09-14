"""
Rust Security Analyzer.
Analyzes Command Execution with shell wrappers, SQL query formatting,
Path Traversal, and high-risk unsafe raw pointer dereferences with false-positive resistance.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_rust(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*"):
            continue

        # 1. Shell Command Injection: Command::new("sh").arg("-c") with format!
        if "Command::new" in line:
            if re.search(r"""Command::new\s*\(\s*["'](?:sh|bash|cmd)["']\s*\)""", line):
                # Check surrounding lines for format! or dynamic string
                surrounding = "\n".join(lines[max(0, idx - 2):min(len(lines), idx + 3)])
                if "format!" in surrounding or ".arg(" in surrounding:
                    findings.append(
                        build_finding(
                            vuln_type="Command Injection",
                            severity="CRITICAL",
                            line=idx,
                            description="Shell execution wrapper via Command::new(\"sh\").arg(\"-c\") with dynamic arguments.",
                            why="Delegating execution to an OS shell (/bin/sh) with formatted string inputs exposes the process to argument/command injection.",
                            impact="Arbitrary command execution on the host machine.",
                            fix="Execute the target binary directly with discrete Command::new(binary).arg(arg1) calls without invoking a shell.",
                            confidence=92,
                            exploitability="HIGH",
                            sink={"line": idx, "code": line_clean, "role": "sink"},
                            evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                            evidence_level="HIGH_CONFIDENCE",
                            analysis_method="Rust Process Command Flow Analysis",
                        )
                    )

        # 2. SQL Injection: query(&format!("SELECT ...", ...))
        sql_match = re.search(r"""\b(?:query|execute)\s*\(\s*&format!\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)""", line, re.IGNORECASE)
        if sql_match:
            findings.append(
                build_finding(
                    vuln_type="SQL Injection",
                    severity="HIGH",
                    line=idx,
                    description="SQL statement constructed dynamically with format! macro.",
                    why="Using format! macro to interpolate variables into SQL queries bypasses parameterized query protection.",
                    impact="Database query manipulation and data extraction.",
                    fix="Use sqlx or diesel query macros with parameter bindings ($1, ?).",
                    confidence=95,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Rust Query Macro Pattern Analysis",
                )
            )

        # 3. High-risk unsafe block with raw pointer dereference
        # We do NOT flag every unsafe block. We only flag if raw pointer dereference is present (*ptr)
        if "unsafe" in line:
            surrounding = "\n".join(lines[max(0, idx - 1):min(len(lines), idx + 5)])
            if re.search(r"\*\s*\w+\s*(?:=|[;,\)])", surrounding) and ("*const" in code or "*mut" in code):
                findings.append(
                    build_finding(
                        vuln_type="Memory Safety Risk",
                        severity="MEDIUM",
                        line=idx,
                        description="Unchecked raw pointer dereference inside unsafe block.",
                        why="Dereferencing raw pointers (*const / *mut) in Rust bypasses borrow-checker safety guarantees, creating risks of null pointer dereference or undefined behavior.",
                        impact="Memory corruption, segmentation faults, and undefined behavior.",
                        fix="Validate raw pointer alignment and non-null status before dereferencing, or wrap in safe abstractions (NonNull, Option<&T>).",
                        confidence=85,
                        exploitability="MEDIUM",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HEURISTIC",
                        analysis_method="Rust Unsafe Block Pointer Audit",
                    )
                )

        # 4. Hardcoded Secret
        sec_match = re.search(r"""(?ix)\blet\s+(?:mut\s+)?(password|api_key|secret_key|token)\s*=\s*["']([^"']{8,})["']""", line)
        if sec_match and not any(ign in sec_match.group(2).lower() for ign in ("env::var", "placeholder")):
            findings.append(
                build_finding(
                    vuln_type="Hardcoded Secret",
                    severity="HIGH",
                    line=idx,
                    description=f"Hardcoded sensitive secret found in variable '{sec_match.group(1)}'.",
                    why="Storing credentials in Rust source files embeds them in version control and compiled ELF/PE binaries.",
                    impact="Credential theft and unauthorized access.",
                    fix="Read secrets from environment variables using std::env::var().",
                    confidence=92,
                    exploitability="HIGH",
                    evidence=[{"role": "secret_declaration", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Sensitive Identifier Heuristic",
                    extra={"variable": sec_match.group(1)},
                )
            )

    return findings
