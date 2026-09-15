"""
Comprehensive Verification Test for SecureCode AI PDF Report Export Flow.
Verifies:
1. Guest / unauthenticated request to /reports/pdf is blocked with 401.
2. Invalid token request is rejected with 401.
3. Production origin (https://buddhadeb-pan.github.io) OPTIONS preflight on /reports/pdf succeeds with CORS headers.
4. Production origin authenticated POST /reports/pdf succeeds and returns application/pdf bytes.
5. Development origin (http://localhost:5173) authenticated POST /reports/pdf succeeds.
6. PDF response structure has correct Content-Type, Content-Disposition, and %PDF magic bytes.
"""

import os
import uuid

# Force test DB isolation
os.environ["USE_TEST_DB"] = "1"

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

PROD_ORIGIN = "https://buddhadeb-pan.github.io"
DEV_ORIGIN = "http://localhost:5173"

SAMPLE_PAYLOAD = {
    "file_name": "auth_service.py",
    "language": "Python",
    "code": "def authenticate(user, password):\n    query = f\"SELECT * FROM users WHERE username = '{user}'\"\n    return query\n",
    "security_score": 75,
    "issues_found": 1,
    "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
    "vulnerabilities": [
        {
            "id": 1,
            "type": "SQL Injection",
            "severity": "HIGH",
            "line": 2,
            "description": "User input directly formatted into SQL query string.",
            "recommendation": "Use parameterized queries.",
        }
    ],
    "ai_security_insight": {
        "analysis_summary": "Detected critical SQL injection risk in authentication routine.",
        "risk_level": "High",
    },
    "ai_remediation": {
        "fix_explanation": "Replace raw f-string SQL query with ORM or parameterized query.",
    },
    "secure_code": "def authenticate(user, password):\n    query = \"SELECT * FROM users WHERE username = :user\"\n    return query\n",
    "ai_comparison": {
        "security": "Parameterized queries eliminate SQL injection vulnerability.",
        "performance": "Query plan caching improves throughput.",
    },
    "analysis_time_ms": 142.5,
    "analysis_time_seconds": 0.14,
}


def run_tests():
    print("=" * 60)
    print("TESTING SECURECODE AI PDF REPORT EXPORT FLOW")
    print("=" * 60)

    # 1. Unauthenticated request must be blocked (Guest protection)
    print("\n[Step 1] Verifying guest / unauthenticated access to /reports/pdf is blocked...")
    res = client.post("/reports/pdf", json=SAMPLE_PAYLOAD)
    assert res.status_code == 401, f"Expected 401 for guest, got {res.status_code}"
    assert "detail" in res.json()
    print("  [PASS] Unauthenticated request correctly blocked with 401 Unauthorized.")

    # 2. Invalid token must be rejected
    print("\n[Step 2] Verifying invalid Bearer token is rejected...")
    res = client.post(
        "/reports/pdf",
        headers={"Authorization": "Bearer invalid_token_12345"},
        json=SAMPLE_PAYLOAD,
    )
    assert res.status_code == 401, f"Expected 401 for invalid token, got {res.status_code}"
    print("  [PASS] Invalid token rejected with 401.")

    # 3. Register and login a valid user to obtain JWT
    unique_email = f"pdf_user_{uuid.uuid4().hex[:8]}@example.com"
    print(f"\n[Step 3] Registering and authenticating user ({unique_email})...")
    reg_res = client.post(
        "/auth/register",
        json={"name": "PDF Test User", "email": unique_email, "password": "SecurePassword2026!"},
    )
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"

    login_res = client.post(
        "/auth/login",
        json={"email": unique_email, "password": "SecurePassword2026!"},
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    print("  [PASS] User authenticated, access token issued.")

    # 4. Production OPTIONS preflight on /reports/pdf
    print(f"\n[Step 4] Testing production OPTIONS preflight from {PROD_ORIGIN} on /reports/pdf...")
    preflight = client.options(
        "/reports/pdf",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, authorization",
        },
    )
    assert preflight.status_code == 200, f"Preflight failed: {preflight.status_code}"
    assert preflight.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert preflight.headers.get("access-control-allow-credentials") == "true"
    print("  [PASS] Production OPTIONS preflight succeeded with 200 OK.")

    # 5. Production authenticated PDF download request
    print(f"\n[Step 5] Testing production authenticated POST /reports/pdf from {PROD_ORIGIN}...")
    pdf_res = client.post(
        "/reports/pdf",
        headers={
            "Origin": PROD_ORIGIN,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=SAMPLE_PAYLOAD,
    )
    assert pdf_res.status_code == 200, f"PDF request failed ({pdf_res.status_code}): {pdf_res.text}"
    assert pdf_res.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert pdf_res.headers.get("access-control-allow-credentials") == "true"
    assert "application/pdf" in pdf_res.headers.get("content-type", "")
    assert "attachment" in pdf_res.headers.get("content-disposition", "")
    assert pdf_res.content.startswith(b"%PDF-"), "Response is not a valid PDF document (missing %PDF- header)"
    assert len(pdf_res.content) > 1000, "PDF content unexpectedly small"
    print(f"  [PASS] Production PDF generated successfully ({len(pdf_res.content)} bytes).")

    # 6. Development authenticated PDF download request
    print(f"\n[Step 6] Testing development authenticated POST /reports/pdf from {DEV_ORIGIN}...")
    dev_pdf_res = client.post(
        "/reports/pdf",
        headers={
            "Origin": DEV_ORIGIN,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=SAMPLE_PAYLOAD,
    )
    assert dev_pdf_res.status_code == 200, f"Dev PDF request failed: {dev_pdf_res.status_code}"
    assert dev_pdf_res.headers.get("access-control-allow-origin") == DEV_ORIGIN
    assert dev_pdf_res.content.startswith(b"%PDF-")
    print(f"  [PASS] Development PDF generated successfully ({len(dev_pdf_res.content)} bytes).")

    print("\n" + "=" * 60)
    print("ALL PDF REPORT FLOW VERIFICATION TESTS PASSED (6/6)!")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
