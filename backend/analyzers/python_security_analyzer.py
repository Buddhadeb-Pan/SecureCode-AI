"""
Python Security Analyzer.
Coordinates AST-level taint analysis for SQLi, Command Injection, XSS, and Secrets,
while extending coverage to Path Traversal, SSRF, Deserialization, Code Injection,
Weak Crypto, and Insecure Randomness.
"""

import ast
import re
from typing import List, Dict, Any

from python_taint_analyzer import analyze_python_sql_injection
from command_injection_analyzer import analyze_python_command_injection
from xss_analyzer import analyze_python_xss
from hardcoded_secret_analyzer import analyze_python_hardcoded_secrets
from analyzers.common import build_finding


def analyze_python(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. Advanced AST SQL Injection
    try:
        sql_res = analyze_python_sql_injection(code)
        if sql_res and isinstance(sql_res, dict) and sql_res.get("findings"):
            for f in sql_res["findings"]:
                findings.append(_normalize_existing_finding(f, "AST + Data-Flow Taint Analysis"))
    except Exception as err:
        print(f"[PY ANALYZER] SQLi analysis error: {err}")

    # 2. Advanced AST Command Injection
    try:
        cmd_res = analyze_python_command_injection(code)
        if cmd_res and isinstance(cmd_res, dict) and cmd_res.get("findings"):
            for f in cmd_res["findings"]:
                findings.append(_normalize_existing_finding(f, "AST + Process Execution Taint Analysis"))
    except Exception as err:
        print(f"[PY ANALYZER] Command Injection analysis error: {err}")

    # 3. Advanced AST XSS
    try:
        xss_res = analyze_python_xss(code)
        if xss_res and isinstance(xss_res, dict) and xss_res.get("findings"):
            for f in xss_res["findings"]:
                findings.append(_normalize_existing_finding(f, "AST + Template & HTML Sink Analysis"))
    except Exception as err:
        print(f"[PY ANALYZER] XSS analysis error: {err}")

    # 4. Advanced Hardcoded Secret (Entropy + Token Detection)
    try:
        secret_res = analyze_python_hardcoded_secrets(code)
        if secret_res and isinstance(secret_res, dict) and secret_res.get("findings"):
            for f in secret_res["findings"]:
                findings.append(_normalize_existing_finding(f, "AST + Shannon Entropy + Token Pattern Heuristics"))
    except Exception as err:
        print(f"[PY ANALYZER] Secret analysis error: {err}")

    # 5. Contextual AST Analysis for Additional Categories
    try:
        extra_findings = _analyze_python_ast_contextual(code)
        findings.extend(extra_findings)
    except Exception as err:
        print(f"[PY ANALYZER] Contextual AST analysis error: {err}")

    return findings


def _normalize_existing_finding(finding: Dict[str, Any], method: str) -> Dict[str, Any]:
    vuln_type = finding.get("type", "Security Issue")
    line = finding.get("line") or finding.get("primary_line") or 0
    aff = finding.get("affected_lines") or [line]
    
    extra = {}
    for k in ("variable", "secret_format", "entropy", "placeholder", "buffer", "buffer_size"):
        if k in finding:
            extra[k] = finding[k]

    return build_finding(
        vuln_type=vuln_type,
        severity=finding.get("severity", "HIGH"),
        line=line,
        description=finding.get("description", "Vulnerability detected in source code."),
        why=finding.get("why", "Untrusted data flow or unsafe configuration introduces security risk."),
        impact=finding.get("impact", "An attacker could compromise the application integrity or data confidentiality."),
        fix=finding.get("fix", "Apply standard secure coding practices and parameterization."),
        confidence=finding.get("confidence", 90),
        exploitability=finding.get("exploitability", "HIGH"),
        affected_lines=aff,
        source=finding.get("source"),
        sink=finding.get("sink"),
        evidence=finding.get("evidence", []),
        evidence_level=finding.get("evidence_level", "CONFIRMED"),
        analysis_method=finding.get("analysis_method", method),
        extra=extra,
    )


class PythonContextVisitor(ast.NodeVisitor):
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.findings: List[Dict[str, Any]] = []
        self.user_inputs: Dict[str, int] = {}

    def visit_Assign(self, node: ast.Assign):
        # Track user input sources: input(), request.args.get(), etc.
        source_line = node.lineno
        is_user_input = False
        if isinstance(node.value, ast.Call):
            func_name = self._get_call_name(node.value.func)
            if func_name in ("input", "request.args.get", "request.form.get", "request.values.get", "request.get_json"):
                is_user_input = True

        if is_user_input:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.user_inputs[target.id] = source_line

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        line = node.lineno

        # 1. Unsafe Deserialization: pickle.loads, pickle.load, _pickle.loads
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "cPickle.loads"):
            code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
            self.findings.append(
                build_finding(
                    vuln_type="Insecure Deserialization",
                    severity="CRITICAL",
                    line=line,
                    description=f"Dangerous deserialization via {func_name} detected.",
                    why="Python pickle is not secure against erroneous or maliciously constructed data. Untrusted byte streams can execute arbitrary Python bytecode during unpickling.",
                    impact="Remote Code Execution (RCE) and complete host compromise.",
                    fix="Use safe serialization formats like JSON, protocol buffers, or hmac-verified signatures instead of pickle.",
                    confidence=95,
                    exploitability="HIGH",
                    evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                    evidence_level="CONFIRMED",
                    analysis_method="AST Call Analysis",
                )
            )

        # 2. Unsafe YAML loading: yaml.load without SafeLoader
        elif func_name in ("yaml.load", "ruamel.yaml.load"):
            has_safe_loader = any(
                isinstance(kw.value, ast.Name) and "Safe" in kw.value.id
                for kw in node.keywords if kw.arg == "Loader"
            )
            if not has_safe_loader:
                code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
                self.findings.append(
                    build_finding(
                        vuln_type="Insecure Deserialization",
                        severity="CRITICAL",
                        line=line,
                        description="Insecure YAML loading via yaml.load without SafeLoader.",
                        why="Standard yaml.load can instantiate arbitrary Python objects through custom YAML tags.",
                        impact="Arbitrary code execution upon parsing malicious YAML document.",
                        fix="Use yaml.safe_load() or specify Loader=yaml.SafeLoader.",
                        confidence=94,
                        exploitability="HIGH",
                        evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                        evidence_level="CONFIRMED",
                        analysis_method="AST Keyword Argument Validation",
                    )
                )

        # 3. Dynamic Code Execution: eval, exec
        elif func_name in ("eval", "exec"):
            code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
            # Don't flag empty or literal literals
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    build_finding(
                        vuln_type="Code Injection",
                        severity="CRITICAL",
                        line=line,
                        description=f"Dynamic code evaluation using {func_name}(...) on non-literal expression.",
                        why="Direct evaluation of non-constant strings allows arbitrary Python statements to run in the current execution scope.",
                        impact="Arbitrary code execution within application privileges.",
                        fix="Avoid dynamic evaluation; use ast.literal_eval() for data parsing or structured dispatch maps.",
                        confidence=92,
                        exploitability="HIGH",
                        evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                        evidence_level="HIGH_CONFIDENCE",
                        analysis_method="AST Dynamic Execution Analysis",
                    )
                )

        # 4. Path Traversal in open() with variable
        elif func_name in ("open", "io.open", "os.open"):
            if node.args and isinstance(node.args[0], (ast.Name, ast.BinOp, ast.JoinedStr)):
                # Check if user input is involved or string concatenation is used
                arg0 = node.args[0]
                is_tainted = False
                source_line = line
                if isinstance(arg0, ast.Name) and arg0.id in self.user_inputs:
                    is_tainted = True
                    source_line = self.user_inputs[arg0.id]
                elif isinstance(arg0, (ast.BinOp, ast.JoinedStr)):
                    # Concatenation or f-string in file open
                    is_tainted = True

                if is_tainted:
                    code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
                    self.findings.append(
                        build_finding(
                            vuln_type="Path Traversal",
                            severity="HIGH",
                            line=line,
                            description="File opened using dynamic path construction with potential user control.",
                            why="Path parameters concatenated into filesystem calls without directory traversal validation can allow access outside intended directories (e.g., ../../etc/passwd).",
                            impact="Unauthorized disclosure of sensitive system and configuration files.",
                            fix="Validate paths using os.path.abspath and ensure it starts with a trusted base directory, or use pathlib.Path.resolve().",
                            confidence=88,
                            exploitability="HIGH",
                            affected_lines=[source_line, line] if source_line != line else [line],
                            sink={"line": line, "code": code_line.strip(), "role": "sink"},
                            evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                            evidence_level="HIGH_CONFIDENCE",
                            analysis_method="AST Path Concatenation Check",
                        )
                    )

        # 5. SSRF in requests.get / urllib with dynamic URL
        elif func_name in ("requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post"):
            if node.args and isinstance(node.args[0], (ast.Name, ast.BinOp, ast.JoinedStr)):
                arg0 = node.args[0]
                is_tainted = False
                source_line = line
                if isinstance(arg0, ast.Name) and arg0.id in self.user_inputs:
                    is_tainted = True
                    source_line = self.user_inputs[arg0.id]
                elif isinstance(arg0, (ast.BinOp, ast.JoinedStr)):
                    is_tainted = True

                if is_tainted:
                    code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
                    self.findings.append(
                        build_finding(
                            vuln_type="Server-Side Request Forgery (SSRF)",
                            severity="HIGH",
                            line=line,
                            description=f"Outbound HTTP request via {func_name} with dynamic destination.",
                            why="Accepting unvalidated target URLs allows attackers to coerce the server into issuing HTTP requests to internal networks, cloud metadata services (169.254.169.254), or localhost.",
                            impact="Access to internal services, cloud instance credentials, and private internal endpoints.",
                            fix="Validate target URLs against an explicit allowlist and disallow private IP ranges (RFC 1918 / loopback / link-local).",
                            confidence=87,
                            exploitability="HIGH",
                            affected_lines=[source_line, line] if source_line != line else [line],
                            sink={"line": line, "code": code_line.strip(), "role": "sink"},
                            evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                            evidence_level="HIGH_CONFIDENCE",
                            analysis_method="AST Outbound Request Analysis",
                        )
                    )

        # 6. Weak Cryptography: hashlib.md5 / hashlib.sha1
        elif func_name in ("hashlib.md5", "hashlib.sha1"):
            code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
            self.findings.append(
                build_finding(
                    vuln_type="Weak Cryptography",
                    severity="MEDIUM",
                    line=line,
                    description=f"Use of broken or cryptographically weak hash algorithm ({func_name}).",
                    why="MD5 and SHA-1 have known collision vulnerabilities and are unsuitable for digital signatures or password hashing.",
                    impact="Collision attacks, hash tampering, and weak credential protection.",
                    fix="Use SHA-256 (hashlib.sha256) or SHA-3 for integrity, and Argon2/bcrypt for passwords.",
                    confidence=95,
                    exploitability="LOW",
                    evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                    evidence_level="CONFIRMED",
                    analysis_method="AST Crypto API Verification",
                )
            )

        # 7. Insecure Randomness: random.random / randint in security contexts (token, secret, key)
        elif func_name in ("random.random", "random.randint", "random.choice"):
            code_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
            line_lower = code_line.lower()
            if any(k in line_lower for k in ("token", "secret", "key", "password", "auth", "session", "otp")):
                self.findings.append(
                    build_finding(
                        vuln_type="Insecure Randomness",
                        severity="HIGH",
                        line=line,
                        description="Pseudorandom number generator 'random' used for security-sensitive token/key generation.",
                        why="The standard 'random' module uses the Mersenne Twister algorithm, which is completely deterministic and predictable once 624 outputs are observed.",
                        impact="Attackers can predict future session tokens, reset tokens, or cryptographic keys.",
                        fix="Use the cryptographically secure 'secrets' module (e.g. secrets.token_hex(), secrets.randbelow()) or os.urandom().",
                        confidence=93,
                        exploitability="HIGH",
                        evidence=[{"role": "sink", "line": line, "code": code_line.strip()}],
                        evidence_level="CONFIRMED",
                        analysis_method="AST Sensitive Context + PRNG Check",
                    )
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""


def _analyze_python_ast_contextual(code: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    lines = code.splitlines()
    visitor = PythonContextVisitor(lines)
    visitor.visit(tree)
    return visitor.findings
