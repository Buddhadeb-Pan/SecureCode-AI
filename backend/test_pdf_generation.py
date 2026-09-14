"""
Test suite for PDF generation.
"""

from pdf_generator import generate_security_pdf


def test_pdf_generation():
    sample_data = {
        "file_name": "app.js",
        "language": "JavaScript",
        "code": "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send(req.query.q));",
        "security_score": 82,
        "issues_found": 1,
        "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "vulnerabilities": [
            {
                "id": 1,
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "confidence": 95,
                "cwe": "CWE-79",
                "owasp": "A03:2021-Injection",
                "line": 3,
                "primary_line": 3,
                "affected_lines": [3],
                "description": "Unsanitized dynamic data reflected in response.",
                "why": "Printing request parameters directly in the response enables reflected XSS.",
                "impact": "Session hijacking and credential theft.",
                "fix": "Sanitize and escape input before sending response.",
                "evidence": [{"role": "sink", "line": 3, "code": "res.send(req.query.q)"}],
                "analysis_method": "DOM Sink Taint Tracking",
            }
        ],
        "ai_security_insight": {
            "why_it_matters": "Input reflection creates high risk of browser script execution.",
            "potential_impact": "Compromised client sessions.",
            "confidence": 90,
        },
        "ai_remediation": {
            "title": "Escape HTML outputs",
            "summary": "Implement strict contextual HTML escaping.",
            "actions": ["Use escapeHtml library", "Configure CSP header"],
        },
        "secure_code": "const express = require('express');\nconst app = express();\nconst escapeHtml = require('escape-html');\napp.get('/', (req, res) => res.send(escapeHtml(req.query.q)));",
        "ai_comparison": {
            "original_security_status": "Vulnerable",
            "corrected_security_status": "Protected",
            "original_time_complexity": "O(1)",
            "corrected_time_complexity": "O(n)",
            "original_space_complexity": "O(1)",
            "corrected_space_complexity": "O(n)",
            "complexity_reason": "Escaping requires scanning the input string once.",
            "final_recommendation": "Deploy secure version with output escaping.",
        },
        "analysis_time_ms": 120.5,
    }

    pdf_bytes = generate_security_pdf(sample_data)
    assert len(pdf_bytes) > 1000, f"PDF byte size too small: {len(pdf_bytes)}"
    assert pdf_bytes.startswith(b"%PDF-"), "Output does not start with PDF magic bytes"

    # Test with unescaped HTML/XML characters (<script>, <div>, &, <XSS>)
    xml_data = dict(sample_data)
    xml_data["vulnerabilities"] = [
        {
            "id": 1,
            "type": "Cross-Site Scripting <XSS>",
            "severity": "HIGH",
            "description": "Found <script>alert(1)</script> inside <div> tag & unescaped.",
            "why": "Unsanitized user data in <script> tags leads to arbitrary execution.",
            "impact": "Session hijack via <script> & stolen document.cookie",
            "fix": "Use textContent instead of <div> and escape & < > characters.",
            "evidence": [{"line": 3, "code": "el.innerHTML = '<div>' + docName + '</div>';"}],
        }
    ]
    xml_data["ai_security_insight"] = {
        "why_it_matters": "XSS allows executing <script> in browser & stealing tokens.",
        "potential_impact": "Session takeover if cookies lack HttpOnly <flag>.",
    }
    xml_data["ai_comparison"] = {
        "original_security_status": "Vulnerable <XSS>",
        "corrected_security_status": "Safe & Sanitized",
        "complexity_reason": "O(1) < O(n) complexity comparison",
    }
    pdf_xml_bytes = generate_security_pdf(xml_data)
    assert pdf_xml_bytes.startswith(b"%PDF-"), "Failed to generate PDF with XML special characters"

    # Test with multi-page long secure code (previously caused ReportLab LayoutError 500)
    long_code_data = dict(sample_data)
    long_code_data["secure_code"] = "\n".join([f"def secure_handler_{i}():\n    return '{i}' * 20" for i in range(120)])
    long_pdf_bytes = generate_security_pdf(long_code_data)
    assert long_pdf_bytes.startswith(b"%PDF-")
    assert len(long_pdf_bytes) > 5000, f"Long code PDF too small: {len(long_pdf_bytes)}"

    # Test with partial / empty / edge-case payloads
    empty_pdf = generate_security_pdf({})
    assert empty_pdf.startswith(b"%PDF-")

    evil_pdf = generate_security_pdf({
        "file_name": None,
        "language": None,
        "severity_counts": None,
        "vulnerabilities": [None, {}, {"type": None, "severity": None, "confidence": None}],
        "ai_security_insight": None,
        "ai_remediation": None,
        "ai_comparison": None,
        "secure_code": None,
    })
    assert evil_pdf.startswith(b"%PDF-")

    # Test with user's specific screen scenario (secrets / complexity recommendation)
    screen_data = {
        "file_name": "auth_service.py",
        "language": "Python",
        "security_score": 75,
        "issues_found": 1,
        "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "vulnerabilities": [
            {
                "type": "Hardcoded Secret",
                "severity": "HIGH",
                "confidence": 98,
                "cwe": "CWE-798",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "line": 14,
                "description": "Hardcoded API secret token found in production code.",
                "why": "Hardcoded secrets risk exposure via source repository.",
                "impact": "Account takeover and unauthorized API access.",
                "fix": "Store secrets in environment variables.",
            }
        ],
        "ai_comparison": {
            "original_security_status": "Vulnerable",
            "corrected_security_status": "Protected",
            "original_time_complexity": "O(1)",
            "corrected_time_complexity": "O(1)",
            "original_space_complexity": "O(1)",
            "corrected_space_complexity": "O(1)",
            "complexity_reason": "Constant-time request overhead and hashing computational overhead.",
            "final_recommendation": "Deploy the code after configuring environment variables for production secrets.",
        },
        "secure_code": "\n".join([f"import os\nSECRET_{i} = os.getenv('SECRET_{i}')" for i in range(80)]),
    }
    screen_pdf = generate_security_pdf(screen_data)
    assert screen_pdf.startswith(b"%PDF-")
    assert len(screen_pdf) > 4000

    print("test_pdf_generation ALL TESTS PASSED (including long code, multi-page, edge cases).")


if __name__ == "__main__":
    test_pdf_generation()

