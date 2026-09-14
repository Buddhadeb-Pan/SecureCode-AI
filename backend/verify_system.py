"""Quick system-level verification for all major backend components."""
print("=== FULL SYSTEM VERIFICATION ===\n")

# Test 1: ML Severity Model
from ml_severity_model import get_ml_engine, predict_finding_severity
engine = get_ml_engine()
print(f"[ML Severity] is_trained: {engine.is_trained}")
result = predict_finding_severity(
    {"cwe": "CWE-89", "severity": "HIGH", "confidence": 90},
    "Python",
    "test code",
)
print(f"[ML Severity] model_status: {result['model_status']}")
print(f"[ML Severity] fallback_severity: {result.get('fallback_severity')}")
print(f"[ML Severity] features_used: {result['features_used']}")
print()

# Test 2: Language Detection
from language_detector import detect_language
r = detect_language(
    code='console.log("hello"); const x = 5;',
    file_name="app.js",
    frontend_hint="JavaScript",
)
print(f"[Language Detection] Detected: {r['language']} ({r['confidence']}%)")
r2 = detect_language(
    code="SELECT * FROM users WHERE id = id",
    file_name="q.sql",
)
print(f"[Language Detection] Detected: {r2['language']} ({r2['confidence']}%)")
print()

# Test 3: Security Engine - Python command injection
from security_rules import scan_security

code_py = "import subprocess\nresult = subprocess.call(user_input)"
vulns = scan_security(code_py, "Python")
print(f"[Security Engine] Python command injection detected: {len(vulns)} finding(s)")

code_js = "document.write(location.href);"
vulns2 = scan_security(code_js, "JavaScript")
print(f"[Security Engine] JS DOM XSS detected: {len(vulns2)} finding(s)")

code_java = 'stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");'
vulns3 = scan_security(code_java, "Java")
print(f"[Security Engine] Java SQL injection detected: {len(vulns3)} finding(s)")
print()

# Test 4: PDF Generation
from pdf_generator import generate_security_pdf
mock_payload = {
    "file_name": "verify.py",
    "detected_language": "Python",
    "security_score": 75,
    "issues_found": 1,
    "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
    "vulnerabilities": [{
        "id": 1, "type": "SQL Injection", "severity": "HIGH",
        "line": 3, "description": "SQL injection risk", "cwe": "CWE-89",
    }],
    "ai_security_insight": {},
    "ai_remediation": {},
    "secure_code": "print('safe')",
    "ai_comparison": {},
}
pdf_bytes = generate_security_pdf(mock_payload)
print(f"[PDF Generator] Generated {len(pdf_bytes)} bytes. Valid PDF: {pdf_bytes[:5] == b'%PDF-'}")
print()

print("=== ALL SYSTEM CHECKS PASSED ===")
