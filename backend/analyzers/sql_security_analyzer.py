"""
SQL Security Analyzer.
Analyzes dangerous dynamic SQL execution (EXEC / sp_executesql with concatenation),
destructive unconstrained statements, and excessive privilege grants without flagging normal SQL queries.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_sql(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    # Track dynamic query variables constructed with concatenation
    dynamic_sql_vars = set()
    for idx, line in enumerate(lines, start=1):
        if ("+" in line or "||" in line) and "=" in line and "@" in line:
            m = re.search(r"(@\w+)", line)
            if m:
                dynamic_sql_vars.add(m.group(1).lower())

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("--") or line_clean.startswith("/*"):
            continue

        # 1. Dangerous Dynamic SQL: EXEC / EXECUTE with string concatenation
        exec_match = re.search(r"\b(?:EXEC|EXECUTE)\s*\(\s*([^)]+)\)", line, re.IGNORECASE)
        if exec_match:
            arg = exec_match.group(1).strip().lower()
            is_dynamic = ("+" in arg and "@" in arg) or ("||" in arg and "@" in arg) or (arg in dynamic_sql_vars)
            if is_dynamic:
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Dynamic SQL statement constructed using concatenation inside EXEC/EXECUTE.",
                        why="Executing dynamic queries assembled via string concatenation permits secondary SQL injection within database stored procedures and scripts.",
                        impact="Arbitrary database statement execution with database engine privileges.",
                        fix="Use sp_executesql with parameterized parameters (@params) instead of raw string concatenation.",
                        confidence=96,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Dynamic SQL Execution Analysis",
                    )
                )

        # 2. Dangerous Privilege Grants: GRANT ALL PRIVILEGES
        if re.search(r"\bGRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+.*\s+TO\s+['\"`]?public['\"`]?", line, re.IGNORECASE):
            findings.append(
                build_finding(
                    vuln_type="Privilege Escalation Risk",
                    severity="HIGH",
                    line=idx,
                    description="Excessive privileges granted to PUBLIC role.",
                    why="Granting ALL privileges to the PUBLIC role exposes all database objects to any authenticated or guest user.",
                    impact="Unauthorized database modification, table drop, or full data exfiltration.",
                    fix="Follow the principle of least privilege: grant only specific permissions (SELECT, INSERT) to designated roles.",
                    confidence=94,
                    exploitability="MEDIUM",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="SQL DDL Privilege Audit",
                )
            )

        # 3. Unconstrained DELETE / UPDATE without WHERE clause in large scripts
        if re.search(r"^\s*(?:DELETE\s+FROM|UPDATE)\s+[\w.]+\s*;?$", line, re.IGNORECASE):
            # Check if next line has WHERE
            has_where = False
            if idx < len(lines):
                if re.search(r"^\s*WHERE\b", lines[idx], re.IGNORECASE):
                    has_where = True
            if not has_where:
                findings.append(
                    build_finding(
                        vuln_type="Sensitive Data Exposure",
                        severity="MEDIUM",
                        line=idx,
                        description="Unconstrained DELETE or UPDATE statement missing a WHERE clause.",
                        why="Executing DELETE or UPDATE without a WHERE condition mutates or removes all records in the entire table.",
                        impact="Accidental or malicious mass data destruction.",
                        fix="Add an explicit WHERE condition specifying target primary keys or intended criteria.",
                        confidence=85,
                        exploitability="LOW",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HEURISTIC",
                        analysis_method="SQL Statement Boundary Check",
                    )
                )

    return findings
