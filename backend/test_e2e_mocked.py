"""
End-to-End Test Suite for FastAPI /analyze and /reports/pdf endpoints.
Uses FastAPI TestClient with mocked OpenRouter client to prevent API quota consumption.
"""

from unittest.mock import patch
from main import analyze_code, export_pdf_report, CodeRequest
from fastapi import HTTPException

MOCK_AI_RESPONSE = """{
  "engine_assessments": [
    {
      "finding_id": 1,
      "severity": "HIGH",
      "confidence": 95,
      "exploitability": "HIGH",
      "cwe": "CWE-79",
      "description": "Cross-Site Scripting via dynamic document.write",
      "severity_reason": "User parameter reflected into DOM sink",
      "why": "Allows execution of arbitrary JavaScript in victim browser",
      "impact": "Session hijacking and credential theft",
      "fix": "Use textContent or escape input before rendering"
    },
    {
      "finding_id": 2,
      "severity": "HIGH",
      "confidence": 92,
      "exploitability": "HIGH",
      "cwe": "CWE-22",
      "description": "Path Traversal via fs.readFileSync",
      "severity_reason": "Unsanitized path concatenation",
      "why": "Allows traversing directories with ../",
      "impact": "Unauthorized access to server files",
      "fix": "Resolve path and check startsWith"
    }
  ],
  "ai_vulnerabilities": [],
  "security_insight": {
    "why_it_matters": "Input flows to both DOM rendering and filesystem read operations.",
    "potential_impact": "Compromise of client sessions and server-side file disclosure.",
    "confidence": 95
  },
  "remediation": {
    "title": "Validate Path and Sanitize DOM Outputs",
    "summary": "Implement path allowlisting and context-aware output escaping.",
    "actions": [
      "Use path.resolve and verify base directory.",
      "Replace document.write with safe DOM setters."
    ]
  },
  "secure_code_lines": [
    "const express = require('express');",
    "const fs = require('fs');",
    "const path = require('path');",
    "const app = express();",
    "app.get('/file', (req, res) => {",
    "    const fileName = path.basename(req.query.file || '');",
    "    const safePath = path.resolve('./uploads', fileName);",
    "    if (!safePath.startsWith(path.resolve('./uploads'))) {",
    "        return res.status(400).send('Invalid file path');",
    "    }",
    "    const data = fs.readFileSync(safePath, 'utf8');",
    "    res.send(data);",
    "});",
    "app.listen(3000);"
  ],
  "comparison": {
    "original_security_status": "Vulnerable",
    "corrected_security_status": "Protected",
    "original_reason": "Concatenated path and direct DOM output",
    "corrected_reason": "Normalizes file path against directory traversal and removes insecure DOM write sink.",
    "security": "Validated path bounds and eliminated DOM XSS",
    "validation": "Path normalization applied",
    "functionality": "Maintained file serving functionality",
    "maintainability": "Standard Node.js security practices used",
    "performance": "Constant time overhead for path checks",
    "original_time_complexity": "O(1)",
    "corrected_time_complexity": "O(1)",
    "original_space_complexity": "O(1)",
    "corrected_space_complexity": "O(1)",
    "complexity_reason": "Path normalization and bounds verification execute in O(1) auxiliary time.",
    "final_recommendation": "Deploy corrected code with path boundary validation."
  }
}"""


@patch("ai_pipeline.call_ai", return_value=MOCK_AI_RESPONSE)
def test_javascript_e2e(mock_call_ai):
    print("\n--- TEST: E2E JavaScript /analyze ---")
    js_code = """const express = require("express");
const fs = require("fs");

const app = express();

app.get("/file", (req, res) => {
    const fileName = req.query.file;
    const filePath = "./uploads/" + fileName;
    document.write(fileName);
    const data = fs.readFileSync(filePath, "utf8");
    res.send(data);
});

app.listen(3000);"""

    data = analyze_code(CodeRequest(code=js_code, file_name="server.js", language="JavaScript"))

    # 1. Verify Top-Level Frontend Required Keys
    required_keys = [
        "status",
        "file_name",
        "detected_language",
        "language_confidence",
        "language_status",
        "parser_passed",
        "security_score",
        "issues_found",
        "severity_counts",
        "vulnerabilities",
        "ai_security_insight",
        "ai_remediation",
        "secure_code",
        "ai_comparison",
        "analysis_time_ms",
        "analysis_time_seconds",
        "code",
    ]
    for key in required_keys:
        assert key in data, f"Missing required top-level key: {key}"

    assert data["status"] == "success"
    assert data["detected_language"] == "JavaScript"
    assert data["issues_found"] == len(data["vulnerabilities"])

    # 2. Verify Severity Counts Match Exactly
    vulns = data["vulnerabilities"]
    counts = data["severity_counts"]
    expected_critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    expected_high = sum(1 for v in vulns if v.get("severity") == "HIGH")
    expected_medium = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    expected_low = sum(1 for v in vulns if v.get("severity") == "LOW")

    assert counts["critical"] == expected_critical, f"Critical count mismatch: {counts['critical']} vs {expected_critical}"
    assert counts["high"] == expected_high, f"High count mismatch: {counts['high']} vs {expected_high}"
    assert counts["medium"] == expected_medium, f"Medium count mismatch: {counts['medium']} vs {expected_medium}"
    assert counts["low"] == expected_low, f"Low count mismatch: {counts['low']} vs {expected_low}"

    # 3. Verify Comparison Fields (including corrected_reason and complexity fields)
    comp = data["ai_comparison"]
    assert "corrected_reason" in comp and comp["corrected_reason"]
    assert "original_time_complexity" in comp
    assert "corrected_time_complexity" in comp
    assert "original_space_complexity" in comp
    assert "corrected_space_complexity" in comp
    assert "complexity_reason" in comp

    # 4. Verify Single LLM Call
    assert mock_call_ai.call_count == 1, f"Expected exactly 1 LLM call, got {mock_call_ai.call_count}"

    print("  [PASS] E2E JavaScript analysis returned complete frontend payload!")
    print(f"  [PASS] Issues found: {data['issues_found']}, Score: {data['security_score']}")

    # 5. Test PDF Report Generation with this payload
    print("\n--- TEST: E2E POST /reports/pdf ---")
    pdf_response = export_pdf_report(data)
    assert pdf_response.status_code == 200, f"Expected 200 for PDF, got {pdf_response.status_code}"
    assert pdf_response.media_type == "application/pdf"
    assert len(pdf_response.body) > 1000
    assert pdf_response.body.startswith(b"%PDF-")
    print(f"  [PASS] E2E PDF report generated successfully ({len(pdf_response.body)} bytes)!")


def test_empty_code_error():
    print("\n--- TEST: Empty Code Error Handling ---")
    try:
        analyze_code(CodeRequest(code="   ", file_name="empty.py"))
        assert False, "Expected HTTPException 400 for empty code."
    except HTTPException as e:
        assert e.status_code == 400, f"Expected 400 for empty code, got {e.status_code}"
        print("  [PASS] Empty code correctly rejected with HTTP 400.")


@patch("ai_pipeline.call_ai", side_effect=RuntimeError("OpenRouter timeout simulation"))
def test_ai_fallback_resilience(mock_call_ai):
    print("\n--- TEST: Graceful AI Fallback Resilience ---")
    py_code = """username = input()
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)"""

    data = analyze_code(CodeRequest(code=py_code, file_name="db.py", language="Python"))

    assert data["status"] == "success"
    assert data["ai_status"] == "unavailable"
    assert len(data["vulnerabilities"]) > 0, "Deterministic vulnerabilities must still be returned"
    assert data["secure_code"] == py_code, "Secure code should fall back safely"

    print("  [PASS] Backend remained resilient and returned deterministic results when AI was unavailable!")


if __name__ == "__main__":
    test_javascript_e2e()
    test_empty_code_error()
    test_ai_fallback_resilience()
    print("\n==========================================")
    print("ALL E2E INTEGRATION TESTS PASSED!")
    print("==========================================\n")
