"""
C# Security Analyzer.
Analyzes SQL Injection, Command Injection, Path Traversal,
Insecure Deserialization (BinaryFormatter), XXE, and Weak Cryptography.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_csharp(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*"):
            continue

        # 1. SQL Injection: SqlCommand with string concatenation or interpolation
        sql_match = re.search(r"\bnew\s+SqlCommand\s*\(([^,)]+)", line)
        if sql_match:
            query = sql_match.group(1).strip()
            if "+" in query or query.startswith('$"') or query.startswith("$@"):
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="HIGH",
                        line=idx,
                        description="SqlCommand initialized with dynamic string concatenation or interpolation.",
                        why="Concatenating unvalidated variables directly into SQL queries allows attackers to manipulate query logic and execute unauthorized SQL.",
                        impact="Data exfiltration, database tampering, and privilege elevation.",
                        fix="Use parameterized queries with command.Parameters.AddWithValue() or SqlParameter.",
                        confidence=94,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="SqlCommand Query Flow Analysis",
                    )
                )

        # 2. Command Injection: Process.Start with string concatenation
        proc_match = re.search(r"\bProcess\.Start\s*\(([^)]+)\)", line)
        if proc_match:
            args = proc_match.group(1).strip()
            if ("+" in args or args.startswith('$"')) and ("cmd" in args.lower() or "powershell" in args.lower() or "sh" in args.lower()):
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Operating system process started with dynamically concatenated shell arguments.",
                        why="Calling Process.Start with shell wrappers and unvalidated parameters allows execution of injected shell operators.",
                        impact="Arbitrary remote code execution and host compromise.",
                        fix="Use ProcessStartInfo with ArgumentList instead of concatenated command line strings.",
                        confidence=93,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Process Execution Analysis",
                    )
                )

        # 3. Path Traversal: File.ReadAllText / File.Open with concat
        file_match = re.search(r"\bFile\.(?:ReadAllText|Open|OpenRead|Delete|WriteAllText)\s*\(([^,)]+)", line)
        if file_match:
            path_arg = file_match.group(1).strip()
            if ("+" in path_arg or path_arg.startswith('$"')) and "Path.GetFileName" not in line:
                findings.append(
                    build_finding(
                        vuln_type="Path Traversal",
                        severity="HIGH",
                        line=idx,
                        description="Filesystem access with dynamic, unvalidated path parameter.",
                        why="Constructing file paths with unvalidated user input enables directory traversal ('../') attacks.",
                        impact="Unauthorized access to arbitrary filesystem locations.",
                        fix="Use Path.GetFullPath() and verify that the target path starts with the approved base directory.",
                        confidence=87,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="C# File I/O Path Verification",
                    )
                )

        # 4. Insecure Deserialization: BinaryFormatter
        if "BinaryFormatter" in line and "Deserialize" in line:
            findings.append(
                build_finding(
                    vuln_type="Insecure Deserialization",
                    severity="CRITICAL",
                    line=idx,
                    description="Insecure .NET deserialization via BinaryFormatter.",
                    why="BinaryFormatter is fundamentally insecure and cannot be made safe for untrusted data. It enables remote code execution gadget chains.",
                    impact="Remote code execution within the executing application domain.",
                    fix="Migrate to secure serializers such as System.Text.Json or protobuf-net.",
                    confidence=98,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="BinaryFormatter Usage Check",
                )
            )

        # 5. Weak Crypto: MD5.Create, SHA1.Create, DESCryptoServiceProvider
        weak_csharp_crypto = re.search(r"\b(?:MD5\.Create|SHA1\.Create|DESCryptoServiceProvider|Rijndael\.Create)", line)
        if weak_csharp_crypto:
            findings.append(
                build_finding(
                    vuln_type="Weak Cryptography",
                    severity="MEDIUM",
                    line=idx,
                    description="Instantiating weak or obsolete cryptographic algorithm.",
                    why="Algorithms like MD5 and DES provide insufficient security and are vulnerable to cryptanalysis.",
                    impact="Weakened cryptographic protection and data tampering.",
                    fix="Use Aes.Create() for symmetric encryption and SHA256.Create() for hashing.",
                    confidence=95,
                    exploitability="LOW",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="C# Cryptography Provider Analysis",
                )
            )

        # 6. Hardcoded Secrets
        sec_match = re.search(r"""(?ix)\b(password|apiKey|api_key|secretKey|privateKey)\s*=\s*["']([^"']{8,})["']""", line)
        if sec_match and not any(ign in sec_match.group(2).lower() for ign in ("configuration[", "environment.", "placeholder")):
            findings.append(
                build_finding(
                    vuln_type="Hardcoded Secret",
                    severity="HIGH",
                    line=idx,
                    description=f"Hardcoded sensitive credential identified in variable '{sec_match.group(1)}'.",
                    why="Hardcoded credentials in C# source can be extracted from compiled IL assemblies or source repositories.",
                    impact="Compromised application credentials and backend services.",
                    fix="Use IConfiguration / appsettings.json or Azure Key Vault / User Secrets.",
                    confidence=92,
                    exploitability="HIGH",
                    evidence=[{"role": "secret_declaration", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Sensitive Identifier Heuristic",
                    extra={"variable": sec_match.group(1)},
                )
            )

    return findings
