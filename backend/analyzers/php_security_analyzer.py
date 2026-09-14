"""
PHP Security Analyzer.
Analyzes SQL Injection, Reflected XSS, Command Injection,
File Inclusion / Path Traversal, Insecure Deserialization, and SSRF.
"""

import re
from typing import List, Dict, Any
from analyzers.common import build_finding


def analyze_php(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.split("\n")

    user_superglobals = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)"

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("#") or line_clean.startswith("/*"):
            continue

        # 1. SQL Injection: mysqli_query / query with concatenated superglobal or variable
        sql_match = re.search(r"\b(?:mysqli_query|\$conn->query|\$db->query|\$pdo->query|mysql_query)\s*\(([^)]+)\)", line)
        if sql_match:
            query = sql_match.group(1).strip()
            if re.search(user_superglobals, query) or ("." in query and "$" in query):
                findings.append(
                    build_finding(
                        vuln_type="SQL Injection",
                        severity="HIGH",
                        line=idx,
                        description="SQL query constructed via PHP string concatenation with untrusted input.",
                        why="Direct concatenation of request data into SQL statements allows attackers to alter query structures.",
                        impact="Unauthorized database access, data theft, and possible administrative bypass.",
                        fix="Use PDO with prepared statements: $stmt = $pdo->prepare('...'); $stmt->execute([...]);",
                        confidence=96,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="PHP SQL Query Taint Analysis",
                    )
                )

        # 2. Reflected XSS: echo / print with $_GET or $_POST without htmlspecialchars
        xss_match = re.search(r"\b(?:echo|print)\s+([^;]+)", line)
        if xss_match:
            expr = xss_match.group(1)
            if re.search(user_superglobals, expr) and "htmlspecialchars" not in expr and "htmlentities" not in expr:
                findings.append(
                    build_finding(
                        vuln_type="Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        line=idx,
                        description="Direct output of request superglobal without HTML escaping.",
                        why="Printing untrusted user input directly into HTML markup enables reflected Cross-Site Scripting (XSS).",
                        impact="Session hijacking, credential theft, and unauthorized browser actions.",
                        fix="Wrap user output with htmlspecialchars($val, ENT_QUOTES, 'UTF-8').",
                        confidence=95,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="PHP Output Sink Taint Check",
                    )
                )

        # 3. Command Injection: shell_exec, system, exec, passthru, popen
        cmd_match = re.search(r"\b(?:shell_exec|system|exec|passthru|popen)\s*\(([^)]+)\)", line)
        if cmd_match:
            arg = cmd_match.group(1).strip()
            if re.search(user_superglobals, arg) or ("$" in arg and "escapeshellarg" not in arg and "escapeshellcmd" not in arg):
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description="Execution of system command with dynamic, unescaped parameter.",
                        why="Passing dynamic variables to PHP command execution functions allows shell injection if metacharacters are not escaped.",
                        impact="Full server compromise and arbitrary shell execution.",
                        fix="Avoid OS command calls where possible; use escapeshellarg() to sanitize any necessary arguments.",
                        confidence=94,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="PHP Process Execution Analysis",
                    )
                )

        # 4. File Inclusion / Path Traversal: include, require with user input
        inc_match = re.search(r"\b(?:include|include_once|require|require_once)\s*(?:\(?\s*([^;)]+)\)?)", line)
        if inc_match:
            target = inc_match.group(1).strip()
            if re.search(user_superglobals, target) or ("$" in target and not (target.startswith('"') and target.endswith('"'))):
                findings.append(
                    build_finding(
                        vuln_type="File Inclusion",
                        severity="CRITICAL",
                        line=idx,
                        description="Dynamic file inclusion via include/require with user-influenced path.",
                        why="Accepting dynamic file paths in include/require directives enables Local/Remote File Inclusion (LFI/RFI) and arbitrary PHP execution.",
                        impact="Remote code execution or reading local server files.",
                        fix="Use an explicit whitelist of allowed file names: switch($page) { case 'home': require 'home.php'; break; }",
                        confidence=95,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="PHP Include Path Analysis",
                    )
                )

        # 5. Insecure Deserialization: unserialize()
        unser_match = re.search(r"\bunserialize\s*\(([^)]+)\)", line)
        if unser_match:
            arg = unser_match.group(1).strip()
            if "allowed_classes" not in line:
                findings.append(
                    build_finding(
                        vuln_type="Insecure Deserialization",
                        severity="CRITICAL",
                        line=idx,
                        description="PHP unserialize() invoked on dynamic input without allowed_classes restrictions.",
                        why="unserialize() instantiates serialized PHP objects and can trigger magic methods (__wakeup, __destruct) leading to POP gadget chains.",
                        impact="Remote code execution and arbitrary object injection.",
                        fix="Use json_decode() for data serialization or set ['allowed_classes' => false].",
                        confidence=93,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="PHP Object Deserialization Check",
                    )
                )

        # 6. SSRF: file_get_contents / curl with dynamic URL
        ssrf_match = re.search(r"\b(?:file_get_contents|curl_init)\s*\(([^)]+)\)", line)
        if ssrf_match:
            arg = ssrf_match.group(1).strip()
            if re.search(user_superglobals, arg):
                findings.append(
                    build_finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        line=idx,
                        description="Server fetch initiated using direct superglobal URL input.",
                        why="Allowing clients to specify arbitrary request targets can force the server to connect to internal services or cloud metadata.",
                        impact="Unauthorized access to internal networks and cloud credentials.",
                        fix="Validate requested URLs against an allowlist and reject non-HTTP schemes and private IP address ranges.",
                        confidence=91,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="PHP URL Fetch Analysis",
                    )
                )

    return findings
