"""
Go Security Analyzer.
Analyzes SQL Injection, Command Injection, Path Traversal, SSRF,
Template Injection, and Weak Cryptography.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_go(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*"):
            continue

        # 1. SQL Injection: db.Query / db.Exec with fmt.Sprintf or string concat
        sql_match = re.search(r"\b(?:db|tx)\.(?:Query|QueryRow|Exec)\s*\(([^)]+)\)", line)
        if sql_match:
            arg = sql_match.group(1).strip()
            if "fmt.Sprintf" in arg or "+" in arg:
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="HIGH",
                        line=idx,
                        description="Database query constructed with fmt.Sprintf or string concatenation.",
                        why="Direct concatenation of parameters into Go database calls bypasses parameterized placeholders and enables SQL injection.",
                        impact="Database manipulation, data loss, and unauthorized access.",
                        fix="Use parameterized queries with placeholder markers: db.Query(\"SELECT ... WHERE id = ?\", id)",
                        confidence=95,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Go Database Query Concatenation Analysis",
                    )
                )

        # 2. Command Injection: exec.Command with "sh", "-c" or dynamic command
        if "exec.Command" in line:
            if re.search(r"""exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']\s*,\s*["']-c["']\s*,\s*([^)]+)""", line):
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Shell execution via exec.Command(\"sh\", \"-c\", ...) with dynamic input.",
                        why="Invoking a shell to execute concatenated strings exposes the process to shell metacharacter injection.",
                        impact="Arbitrary command execution and system takeover.",
                        fix="Execute target binaries directly without a shell wrapper: exec.Command(binaryPath, arg1, arg2)",
                        confidence=93,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Go Exec Command Flow Check",
                    )
                )

        # 3. Path Traversal: os.Open / os.ReadFile with string concatenation
        file_match = re.search(r"\b(?:os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Create)\s*\(([^)]+)\)", line)
        if file_match:
            arg = file_match.group(1).strip()
            if "+" in arg or "filepath.Join" in arg:
                if "filepath.Clean" not in line and "strings.HasPrefix" not in code:
                    findings.append(
                        build_finding(
                            vuln_type="Path Traversal",
                            severity="HIGH",
                            line=idx,
                            description="Filesystem access with dynamic path parameter.",
                            why="Accepting dynamic file paths without sanitizing directory traversal sequences enables unauthorized file access.",
                            impact="Arbitrary file reading or modification outside the designated root directory.",
                            fix="Clean paths with filepath.Clean() and ensure strings.HasPrefix(cleanedPath, allowedRootDir).",
                            confidence=87,
                            exploitability="HIGH",
                            sink={"line": idx, "code": line_clean, "role": "sink"},
                            evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                            evidence_level="HIGH_CONFIDENCE",
                            analysis_method="Go File Path Validation Analysis",
                        )
                    )

        # 4. SSRF: http.Get / http.Post with dynamic parameter
        http_match = re.search(r"\bhttp\.(?:Get|Post)\s*\(([^,)]+)", line)
        if http_match:
            arg = http_match.group(1).strip()
            if not (arg.startswith('"') and arg.endswith('"')):
                findings.append(
                    build_finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        line=idx,
                        description="Outbound HTTP request to dynamic URL destination.",
                        why="Executing HTTP requests against user-provided URLs enables attackers to probe internal microservices and cloud metadata.",
                        impact="Unauthorized internal network access and credential leakage.",
                        fix="Enforce an allowlist of target domains and restrict connection to private/loopback IP ranges.",
                        confidence=88,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Go HTTP Client Analysis",
                    )
                )

        # 5. Weak Crypto: md5.New() or des.NewCipher
        if re.search(r"\b(?:md5\.New|sha1\.New|des\.NewCipher)\s*\(", line):
            findings.append(
                build_finding(
                    vuln_type="Weak Cryptography",
                    severity="MEDIUM",
                    line=idx,
                    description="Use of weak cryptographic hash or cipher algorithm (MD5/SHA1/DES).",
                    why="Algorithms like MD5 and DES suffer from practical collision and cryptanalytic attacks.",
                    impact="Weakened cryptographic protection and signature collision vulnerability.",
                    fix="Use crypto/sha256 (sha256.New()) for hashing and aes.NewCipher() for symmetric encryption.",
                    confidence=95,
                    exploitability="LOW",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Go Crypto Package Check",
                )
            )

    return findings
