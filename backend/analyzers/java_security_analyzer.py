"""
Java Security Analyzer.
Analyzes SQL Injection, Command Injection, Path Traversal, SSRF,
Insecure Deserialization, XXE, Weak Cryptography, and Hardcoded Secrets
with context-awareness and false-positive resistance.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_java(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    # Check for XXE protection flags
    xxe_protected = "disallow-doctype-decl" in code or "XMLConstants.FEATURE_SECURE_PROCESSING" in code

    # Track variables containing concatenated SQL queries
    concatenated_sql_vars = {}
    for idx, line in enumerate(lines, start=1):
        m = re.search(r'\b(?:String)\s+(\w+)\s*=\s*([^;]+)', line)
        if m:
            var_name = m.group(1)
            expr = m.group(2)
            if ("+" in expr or "String.format" in expr) and re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)', expr, re.IGNORECASE):
                concatenated_sql_vars[var_name] = idx

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*") or line_clean.startswith("*"):
            continue

        # 1. SQL Injection: Statement.executeQuery / executeUpdate with string concatenation
        sql_match = re.search(r"\b(?:stmt|statement)\.(?:executeQuery|executeUpdate|execute)\s*\(([^)]+)\)", line, re.IGNORECASE)
        if sql_match:
            arg = sql_match.group(1).strip()
            tainted_var = next((v for v in concatenated_sql_vars if v == arg or v in arg), None)
            if "+" in arg or "%s" in arg or "String.format" in arg or tainted_var:
                aff_lines = [concatenated_sql_vars[tainted_var], idx] if tainted_var else [idx]
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="HIGH",
                        line=idx,
                        description="Dynamically concatenated SQL query executed via Statement.",
                        why="Direct concatenation of parameters into SQL statements allows user input to break query syntax and execute unauthorized SQL commands.",
                        impact="Database compromise, unauthorized data extraction, and potential authentication bypass.",
                        fix="Use java.sql.PreparedStatement with parameter placeholders ('?') instead of raw Statement concatenation.",
                        confidence=96,
                        exploitability="HIGH",
                        affected_lines=aff_lines,
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="Statement Concatenation Analysis",
                    )
                )

        # 2. Command Injection: Runtime.getRuntime().exec or ProcessBuilder
        cmd_match = re.search(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(([^)]+)\)", line)
        if cmd_match:
            arg = cmd_match.group(1).strip()
            # If dynamic concatenation or string format
            is_concat = "+" in arg or "String.format" in arg
            if is_concat:
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Operating system command executed with dynamically assembled arguments.",
                        why="Passing concatenated command strings to Runtime.exec or ProcessBuilder allows attackers to inject command separators and execute arbitrary system processes.",
                        impact="Full server takeover and unauthorized operating system access.",
                        fix="Avoid invoking the OS shell. Pass the executable name and arguments as discrete elements in a List or String array without string concatenation.",
                        confidence=94,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="JVM Process Execution Analysis",
                    )
                )

        # 3. Path Traversal: new File / new FileInputStream with concat
        file_match = re.search(r"\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(([^)]+)\)", line)
        if file_match:
            arg = file_match.group(1).strip()
            if "+" in arg and not arg.startswith('"') and not arg.endswith('"'):
                findings.append(
                    build_finding(
                        vuln_type="Path Traversal",
                        severity="HIGH",
                        line=idx,
                        description="File object constructed with dynamic path concatenation.",
                        why="Concatenating unvalidated input into file paths allows path traversal sequences ('../') to escape the target directory.",
                        impact="Arbitrary file read, write, or modification outside intended application storage.",
                        fix="Validate file paths with Path.normalize() and verify path.startsWith(baseDir.toPath()).",
                        confidence=88,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Java I/O Path Analysis",
                    )
                )

        # 4. Insecure Deserialization: ObjectInputStream.readObject
        if "readObject()" in line and ("ObjectInputStream" in code or "ois" in line):
            findings.append(
                build_finding(
                    vuln_type="Insecure Deserialization",
                    severity="CRITICAL",
                    line=idx,
                    description="Java deserialization via ObjectInputStream.readObject() detected.",
                    why="Deserializing untrusted ObjectInputStream data can trigger gadget chains in available classpath libraries to achieve remote code execution.",
                    impact="Remote Code Execution (RCE) and system compromise.",
                    fix="Use safe data interchange formats like JSON or Protocol Buffers, or configure an ObjectInputFilter allowlist.",
                    confidence=95,
                    exploitability="HIGH",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Java Deserialization Sink Analysis",
                )
            )

        # 5. XXE: DocumentBuilderFactory / SAXParser without disallow-doctype-decl
        if re.search(r"\b(?:DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance)", line):
            if not xxe_protected:
                findings.append(
                    build_finding(
                        vuln_type="XML External Entity (XXE)",
                        severity="HIGH",
                        line=idx,
                        description="XML parser configured without disabling external DTD / entity processing.",
                        why="Standard Java XML parsers resolve external entities by default, allowing attackers to read local files or perform SSRF via crafted DOCTYPE entities.",
                        impact="Confidential file disclosure (e.g. /etc/passwd) and server-side request forgery.",
                        fix="Set feature 'http://apache.org/xml/features/disallow-doctype-decl' to true before parsing XML.",
                        confidence=91,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="XML Parser Configuration Analysis",
                    )
                )

        # 6. SSRF: new URL(...).openConnection() with dynamic variable
        url_match = re.search(r"\bnew\s+URL\s*\(([^)]+)\)\.openConnection", line)
        if url_match:
            arg = url_match.group(1).strip()
            if not (arg.startswith('"') and arg.endswith('"')):
                findings.append(
                    build_finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        line=idx,
                        description="Outbound network connection initiated with dynamic target URL.",
                        why="Directing URL connections to user-supplied targets allows attackers to query internal services and cloud metadata endpoints.",
                        impact="Internal network port scanning, cloud credential theft, and access to internal REST APIs.",
                        fix="Validate requested URLs against an allowlist of permitted hosts and protocols, and reject internal/loopback IPs.",
                        confidence=90,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="Network Client Target Analysis",
                    )
                )

        # 7. Weak Crypto: DES, Blowfish, MD5, SHA-1
        weak_crypto = re.search(r"""(?:Cipher\.getInstance\s*\(\s*["'](DES|RC4|Blowfish)|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1))""", line, re.IGNORECASE)
        if weak_crypto:
            algo = weak_crypto.group(1) or weak_crypto.group(2)
            findings.append(
                build_finding(
                    vuln_type="Weak Cryptography",
                    severity="MEDIUM",
                    line=idx,
                    description=f"Cryptographic operation initialized with weak or obsolete algorithm '{algo}'.",
                    why="Algorithms like DES, RC4, MD5, and SHA-1 suffer from known structural weaknesses, small key sizes, or collision vulnerabilities.",
                    impact="Compromised data encryption or forged cryptographic signatures.",
                    fix="Use AES-GCM (AES/GCM/NoPadding) for encryption and SHA-256 for secure hashing.",
                    confidence=95,
                    exploitability="LOW",
                    sink={"line": idx, "code": line_clean, "role": "sink"},
                    evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="JCA Algorithm Analysis",
                )
            )

        # 8. Hardcoded Secrets
        sec_match = re.search(r"""(?ix)\b(?:String\s+)?(password|apiKey|api_key|secretKey|privateKey)\s*=\s*["']([^"']{8,})["']""", line)
        if sec_match and not any(ign in sec_match.group(2).lower() for ign in ("system.getenv", "your-", "placeholder")):
            findings.append(
                build_finding(
                    vuln_type="Hardcoded Secret",
                    severity="HIGH",
                    line=idx,
                    description=f"Hardcoded sensitive secret found in field '{sec_match.group(1)}'.",
                    why="Embedding secrets in Java source code exposes them in version control and compiled class bytecode.",
                    impact="Unauthorized access to databases, APIs, or cryptographic subsystems.",
                    fix="Retrieve secrets via System.getenv() or a configuration service (e.g. HashiCorp Vault).",
                    confidence=93,
                    exploitability="HIGH",
                    evidence=[{"role": "secret_declaration", "line": idx, "code": line_clean}],
                    evidence_level="CONFIRMED",
                    analysis_method="Sensitive Identifier Heuristic",
                    extra={"variable": sec_match.group(1)},
                )
            )

    return findings
