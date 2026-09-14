"""
C / C++ Security Analyzer.
Coordinates advanced fixed-buffer tracking and boundary analysis,
and extends checks for Format String vulnerabilities, Memory Safety
(Double-Free / Use-After-Free indicators), and Command Execution.
"""

import re
from typing import List, Dict, Any
from buffer_overflow_analyzer import analyze_c_cpp_buffer_overflow
from analyzers.common import build_finding


def analyze_c_cpp(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. Advanced Buffer Overflow Analyzer (Fixed buffer tracking + boundary analysis)
    try:
        buf_res = analyze_c_cpp_buffer_overflow(code)
        if buf_res and isinstance(buf_res, dict) and buf_res.get("findings"):
            for f in buf_res["findings"]:
                findings.append(_normalize_buffer_finding(f))
    except Exception as err:
        print(f"[C/CPP ANALYZER] Buffer overflow analysis error: {err}")

    # 2. Contextual C/C++ Static Checks (Format strings, memory safety, command injection)
    lines = code.split("\n")
    freed_ptrs: Dict[str, int] = {}

    for idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("/*") or line_clean.startswith("*"):
            continue

        # A. Format String: printf(var) / syslog(priority, var) without format literal
        fmt_match = re.search(r"\b(?:printf|fprintf|syslog|snprintf)\s*\(([^)]+)\)", line)
        if fmt_match:
            args = [a.strip() for a in fmt_match.group(1).split(",")]
            # For printf: if 1st arg is not a string literal
            if fmt_match.group(0).startswith("printf") and len(args) == 1:
                arg0 = args[0]
                if not (arg0.startswith('"') and arg0.endswith('"')):
                    findings.append(
                        build_finding(
                            vuln_type="Format String Vulnerability",
                            severity="HIGH",
                            line=idx,
                            description=f"Format function invoked with dynamic format string '{arg0}'.",
                            why="Passing untrusted variables directly as the format argument to printf() allows attackers to specify format specifiers (%x, %s, %n) to leak memory or write to arbitrary memory locations.",
                            impact="Arbitrary memory read/write, crash, or potential code execution.",
                            fix="Always pass a static string literal format specifier: printf(\"%s\", variable);",
                            confidence=96,
                            exploitability="HIGH",
                            sink={"line": idx, "code": line_clean, "role": "sink"},
                            evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                            evidence_level="CONFIRMED",
                            analysis_method="Format String Analysis",
                        )
                    )

        # B. Memory Safety: Double-Free / Use-After-Free indicators
        free_match = re.search(r"\b(?:free|delete|delete\[\])\s*(?:\(?\s*(\w+)\s*\)?)", line)
        if free_match:
            ptr = free_match.group(1)
            if ptr in freed_ptrs:
                # Double free detected!
                first_line = freed_ptrs[ptr]
                findings.append(
                    build_finding(
                        vuln_type="Memory Safety Risk",
                        severity="HIGH",
                        line=idx,
                        description=f"Double-free detected: pointer '{ptr}' freed again after line {first_line}.",
                        why="Freeing memory twice corrupts memory allocator metadata and can lead to arbitrary write vulnerabilities in the heap.",
                        impact="Heap corruption, Denial of Service, or remote arbitrary code execution.",
                        fix="Set pointer to NULL immediately after freeing it, or use C++ RAII / smart pointers (std::unique_ptr).",
                        confidence=93,
                        exploitability="HIGH",
                        affected_lines=[first_line, idx],
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[
                            {"role": "first_free", "line": first_line, "code": f"free({ptr})"},
                            {"role": "second_free", "line": idx, "code": line_clean},
                        ],
                        evidence_level="CONFIRMED",
                        analysis_method="Pointer Lifecycle Static Analysis",
                    )
                )
            else:
                freed_ptrs[ptr] = idx

        # Check for use-after-free on previously freed pointer
        for ptr, free_line in freed_ptrs.items():
            if idx > free_line and re.search(r"\b" + re.escape(ptr) + r"\s*->|\*" + re.escape(ptr) + r"\b", line):
                findings.append(
                    build_finding(
                        vuln_type="Memory Safety Risk",
                        severity="HIGH",
                        line=idx,
                        description=f"Use-after-free risk: pointer '{ptr}' accessed after being freed on line {free_line}.",
                        why="Dereferencing memory after deallocation can access overwritten or reallocated heap structures.",
                        impact="Heap corruption, information disclosure, and control flow hijacking.",
                        fix="Do not access pointers after deallocation; assign to NULL or use RAII smart pointers.",
                        confidence=91,
                        exploitability="HIGH",
                        affected_lines=[free_line, idx],
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[
                            {"role": "free", "line": free_line, "code": f"free({ptr})"},
                            {"role": "dereference", "line": idx, "code": line_clean},
                        ],
                        evidence_level="CONFIRMED",
                        analysis_method="Pointer Lifecycle Static Analysis",
                    )
                )

        # C. Command Execution: system(...) or popen(...)
        sys_match = re.search(r"\b(?:system|popen)\s*\(([^)]+)\)", line)
        if sys_match:
            arg = sys_match.group(1).strip()
            if not (arg.startswith('"') and arg.endswith('"')):
                findings.append(
                    build_finding(
                        vuln_type="Command Injection",
                        severity="CRITICAL",
                        line=idx,
                        description=f"OS shell command execution via dynamic argument in {line_clean[:25]}.",
                        why="Calling system() or popen() with dynamic input executes commands via /bin/sh. Attackers can append shell metacharacters to execute unintended binaries.",
                        impact="Arbitrary command execution with host application permissions.",
                        fix="Use execve() or posix_spawn() with discrete argument vectors instead of invoking the shell.",
                        confidence=94,
                        exploitability="HIGH",
                        sink={"line": idx, "code": line_clean, "role": "sink"},
                        evidence=[{"role": "sink", "line": idx, "code": line_clean}],
                        evidence_level="CONFIRMED",
                        analysis_method="System Call Parameter Analysis",
                    )
                )

    return findings


def _normalize_buffer_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    line = finding.get("line") or finding.get("primary_line") or 0
    aff = finding.get("affected_lines") or [line]
    extra = {
        "buffer": finding.get("buffer"),
        "buffer_size": finding.get("buffer_size"),
    }

    return build_finding(
        vuln_type="Buffer Overflow Risk",
        severity=finding.get("severity", "HIGH"),
        line=line,
        description=finding.get("description", "Buffer overflow risk detected."),
        why=finding.get("why", "Fixed size buffer receiving unbounded input can overwrite adjacent stack memory."),
        impact=finding.get("impact", "Memory corruption, segmentation fault, or remote code execution via stack smashing."),
        fix=finding.get("fix", "Use bounded input functions (e.g. fgets with buffer size, or std::string in C++)."),
        confidence=finding.get("confidence", 97),
        exploitability=finding.get("exploitability", "HIGH"),
        affected_lines=aff,
        source=finding.get("source"),
        sink=finding.get("sink"),
        evidence=finding.get("evidence", []),
        evidence_level=finding.get("evidence_level", "buffer_overflow_risk_confirmed"),
        analysis_method=finding.get("analysis_method", "C/C++ Buffer Tracking + Boundary Analysis"),
        extra=extra,
    )
