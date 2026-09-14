"""
Swift Security Analyzer.
Analyzes Process Execution with shell wrappers, Path Traversal,
Weak Cryptography (CC_MD5), and Hardcoded Secrets in Swift / iOS / macOS code.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_swift(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*"):
            continue

        # 1. Process Execution with Shell Wrapper
        if "Process()" in line or "Process.run" in line:
            surrounding = "\n".join(lines[max(0, idx - 1):min(len(lines), idx + 5)])
            if ("/bin/sh" in surrounding or "/bin/bash" in surrounding) and ("\\(" in surrounding or "+" in surrounding):
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Process execution delegating to shell with string interpolation.",
                        why="Passing interpolated strings to a shell process allows command metacharacter injection.",
                        impact="Arbitrary command execution on the host macOS/Linux system.",
                        fix="Execute binaries directly with discrete arguments rather than invoking /bin/sh.",
                        confidence=92,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Swift Process Argument Analysis",
                    )
                )

        # 2. Path Traversal: FileManager contents(atPath:) with dynamic interpolation
        file_match = re.search(r"""FileManager\.default\.(?:contents|createFile)\s*\(atPath:\s*([^,)]+)""", line)
        if file_match:
            path_arg = file_match.group(1).strip()
            if "\\(" in path_arg or "+" in path_arg:
                findings.append(
                    build_finding(
                        vuln_type="Path Traversal",
                        severity="HIGH",
                        line=idx,
                        description="FileManager operation performed with dynamic, interpolated path.",
                        why="Unsanitized path strings enable path traversal outside intended sandbox/application directories.",
                        impact="Reading or writing files outside the application sandbox.",
                        fix="Use URL(fileURLWithPath:).standardizedFileURL and verify it starts with approved directory URL.",
                        confidence=87,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Swift File Path Verification",
                    )
                )

        # 3. Weak Cryptography: CC_MD5 or CC_SHA1
        if re.search(r"\b(?:CC_MD5|CC_SHA1)\s*\(", line):
            findings.append(
                build_finding(
                    vuln_type="Weak Cryptography",
                    severity="MEDIUM",
                    line=idx,
                    description="Use of obsolete CommonCrypto hash algorithm (CC_MD5 / CC_SHA1).",
                    why="MD5 and SHA-1 are cryptographically broken and prone to collision attacks.",
                    impact="Potential hash collision and data integrity compromise.",
                    fix="Use CryptoKit (SHA256.hash(data:)) for modern, cryptographically secure hashing.",
                    confidence=96,
                    exploitability="LOW",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="CommonCrypto API Audit",
                )
            )

        # 4. Hardcoded Secrets
        sec_match = re.search(r"""(?ix)\blet\s+(password|apiKey|api_key|secretKey|token)\s*=\s*["']([^"']{8,})["']""", line)
        if sec_match and not any(ign in sec_match.group(2).lower() for ign in ("processinfo.", "placeholder")):
            findings.append(
                build_finding(
                    vuln_type="Hardcoded Secret",
                    severity="HIGH",
                    line=idx,
                    description=f"Hardcoded sensitive secret found in constant '{sec_match.group(1)}'.",
                    why="Storing credentials in Swift source files embeds them in iOS/macOS Mach-O application binaries.",
                    impact="Credential extraction via binary inspection.",
                    fix="Store secrets in the iOS/macOS Keychain or retrieve them at runtime from an authorized server.",
                    confidence=92,
                    exploitability="HIGH",
                    evidence=[{"role": "secret_declaration", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Sensitive Identifier Heuristic",
                    extra={"variable": sec_match.group(1)},
                )
            )

    return findings
