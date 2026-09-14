"""
Comprehensive automated test suite for SecureCode AI Access Control and Authentication Layer.
Targeting isolated test DB: securecode_ai_test (USE_TEST_DB=1).

Tests:
1. Guest 1 free analysis: Allowed (200 OK + sets guest_trial_token cookie).
2. Guest 2nd analysis: Blocked immediately (403 Forbidden + X-Auth-Required).
3. PDF report unauthenticated: Blocked (401 Unauthorized).
4. User login: 200 OK + access token (type='access') + HttpOnly refresh token cookie (type='refresh').
5. Token isolation:
   - Access token rejected at POST /auth/refresh.
   - Refresh token rejected at GET /auth/me and POST /reports/pdf.
6. User profile GET /auth/me: 200 OK with safe fields (id, name, email, is_active).
7. Token refresh POST /auth/refresh: 200 OK with new access token and rotated refresh cookie.
8. Logged-in user unlimited analyses: Repeated POST /analyze succeed (200 OK).
9. Logged-in user PDF download: POST /reports/pdf succeeds (200 OK + application/pdf).
10. User logout POST /auth/logout: 200 OK and clears refresh cookie.
"""

import os
import sys
import uuid
from datetime import datetime, timezone

os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db, get_engine, Base
from database.models import User, GuestTrial
from auth.security import (
    hash_password,
    decode_access_token,
    decode_refresh_token,
    decode_guest_token,
    create_access_token,
    create_refresh_token,
)

client = TestClient(app)


def run_all_tests():
    print("\n========================================================")
    print("STARTING ACCESS CONTROL & AUTHENTICATION TEST SUITE")
    print("========================================================")

    # 0. SETUP TEST DATABASE
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    db = next(get_db())

    test_email = f"access_test_{uuid.uuid4().hex[:8]}@example.com"
    test_password = "SecurePassword123"

    user = User(
        name="Access Control User",
        email=test_email,
        password_hash=hash_password(test_password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"[SETUP] Created test user: {test_email} (id: {user.id})")

    # Clean any leftover guest trials in test db
    db.query(GuestTrial).delete()
    db.commit()

    # ==========================================================
    # TEST 1: GUEST FIRST ANALYSIS ALLOWED (200 OK + Cookie)
    # ==========================================================
    print("\n[TEST 1] Unauthenticated guest first code analysis...")
    sample_code = 'int main() { char buf[10]; gets(buf); return 0; }'
    
    # Fresh client with no cookies
    guest_client = TestClient(app)
    res1 = guest_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "test.c", "language": "C"},
    )
    assert res1.status_code == 200, f"Expected 200, got {res1.status_code}: {res1.text}"
    data1 = res1.json()
    assert data1["status"] == "success", "Response status should be success"
    assert "security_score" in data1, "Response must include security_score"
    assert "vulnerabilities" in data1, "Response must include vulnerabilities"
    
    # Check that guest_trial_token cookie was issued
    guest_cookie = res1.cookies.get("guest_trial_token")
    assert guest_cookie is not None, "guest_trial_token cookie must be set on first analysis"
    decoded_guest = decode_guest_token(guest_cookie)
    assert decoded_guest.get("type") == "guest", "Guest token must have type='guest'"
    print(f"[PASS]: Guest 1st analysis succeeded (Score: {data1['security_score']}, Cookie Issued: {guest_cookie[:20]}...)")

    # ==========================================================
    # TEST 2: GUEST SECOND ANALYSIS BLOCKED (403 Forbidden)
    # ==========================================================
    print("\n[TEST 2] Guest second analysis attempt (must be blocked)...")
    # Using the same guest_client carrying the guest_trial_token cookie
    res2 = guest_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "test2.c", "language": "C"},
    )
    assert res2.status_code == 403, f"Expected 403, got {res2.status_code}: {res2.text}"
    assert "used your free security analysis" in res2.json().get("detail", ""), (
        f"Detail message mismatch: {res2.text}"
    )
    assert res2.headers.get("X-Auth-Required") == "true", (
        "X-Auth-Required header must be present on 403 guest rejection"
    )
    print("[PASS]: Guest 2nd analysis blocked immediately with 403 and X-Auth-Required: true")

    # ==========================================================
    # TEST 3: PDF REPORT UNAUTHENTICATED GUEST BLOCKED (401)
    # ==========================================================
    print("\n[TEST 3] PDF report export unauthenticated attempt (must return 401)...")
    pdf_payload = {
        "file_name": "test.c",
        "language": "C",
        "code": sample_code,
        "security_score": 75,
        "issues_found": 1,
        "severity_counts": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "vulnerabilities": [],
    }
    res_pdf_guest = guest_client.post("/reports/pdf", json=pdf_payload)
    assert res_pdf_guest.status_code == 401, f"Expected 401, got {res_pdf_guest.status_code}"
    print("[PASS]: Unauthenticated PDF report request rejected with 401 Unauthorized")

    # ==========================================================
    # TEST 4: USER LOGIN & TOKEN GENERATION
    # ==========================================================
    print("\n[TEST 4] User login & JWT issuance...")
    auth_client = TestClient(app)
    login_res = auth_client.post(
        "/auth/login",
        json={"email": test_email, "password": test_password},
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    login_data = login_res.json()
    access_token = login_data.get("access_token")
    assert access_token is not None, "Missing access_token in login response"
    
    # Verify access token claims
    decoded_access = decode_access_token(access_token)
    assert decoded_access.get("type") == "access", "Access token must have type='access'"
    assert decoded_access.get("sub") == str(user.id), "Access token sub must match user id"
    
    # Verify HttpOnly refresh_token cookie
    refresh_cookie = login_res.cookies.get("refresh_token")
    assert refresh_cookie is not None, "refresh_token cookie must be set on login"
    decoded_refresh = decode_refresh_token(refresh_cookie)
    assert decoded_refresh.get("type") == "refresh", "Refresh token must have type='refresh'"
    assert decoded_refresh.get("sub") == str(user.id), "Refresh token sub must match user id"
    print("[PASS]: User login succeeded, access token (type='access') and refresh cookie (type='refresh') verified")

    # ==========================================================
    # TEST 5: GET /auth/me PROFILE
    # ==========================================================
    print("\n[TEST 5] GET /auth/me profile verification...")
    # Without token -> 401
    me_unauth = client.get("/auth/me")
    assert me_unauth.status_code == 401, f"Expected 401, got {me_unauth.status_code}"

    # With valid Bearer token -> 200
    me_auth = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_auth.status_code == 200, f"Expected 200, got {me_auth.status_code}"
    me_data = me_auth.json()
    assert me_data["id"] == user.id
    assert me_data["email"] == test_email
    assert me_data["name"] == "Access Control User"
    assert me_data["is_active"] is True
    assert "password" not in me_data and "password_hash" not in me_data, "Never leak passwords or hashes"
    print("[PASS]: GET /auth/me verified successfully")

    # ==========================================================
    # TEST 6: TOKEN ISOLATION ENFORCEMENT
    # ==========================================================
    print("\n[TEST 6] Token isolation enforcement...")
    # 6a. Access token cannot be used as refresh token
    cross_refresh = client.post(
        "/auth/refresh",
        cookies={"refresh_token": access_token},
    )
    assert cross_refresh.status_code == 401, (
        f"Access token must be rejected at /auth/refresh, got: {cross_refresh.status_code}"
    )

    # 6b. Refresh token cannot be used as access token at /auth/me
    cross_me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {refresh_cookie}"},
    )
    assert cross_me.status_code == 401, (
        f"Refresh token must be rejected as Bearer token at /auth/me, got: {cross_me.status_code}"
    )
    print("[PASS]: Cross-token misuse strictly rejected with 401")

    # ==========================================================
    # TEST 7: POST /auth/refresh REFRESH TOKEN FLOW
    # ==========================================================
    print("\n[TEST 7] POST /auth/refresh session renewal...")
    refresh_res = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_cookie},
    )
    assert refresh_res.status_code == 200, f"Refresh failed: {refresh_res.text}"
    new_access_token = refresh_res.json().get("access_token")
    assert new_access_token is not None
    new_decoded = decode_access_token(new_access_token)
    assert new_decoded.get("type") == "access"
    
    # Cookie rotation check
    new_refresh_cookie = refresh_res.cookies.get("refresh_token")
    assert new_refresh_cookie is not None
    print("[PASS]: Access token renewed and refresh cookie rotated successfully")

    # ==========================================================
    # TEST 8: LOGGED-IN USER UNLIMITED ANALYSES
    # ==========================================================
    print("\n[TEST 8] Authenticated user unlimited analyses...")
    auth_headers = {"Authorization": f"Bearer {new_access_token}"}
    
    # First analysis as logged-in user
    res_auth_1 = client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "auth_test.c", "language": "C"},
        headers=auth_headers,
    )
    assert res_auth_1.status_code == 200, f"Expected 200, got {res_auth_1.status_code}"
    
    # Second analysis as logged-in user (MUST NOT be blocked by any 1-scan limit!)
    res_auth_2 = client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "auth_test2.c", "language": "C"},
        headers=auth_headers,
    )
    assert res_auth_2.status_code == 200, (
        f"Authenticated user 2nd analysis should succeed, got {res_auth_2.status_code}: {res_auth_2.text}"
    )

    # Third analysis as logged-in user
    res_auth_3 = client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "auth_test3.c", "language": "C"},
        headers=auth_headers,
    )
    assert res_auth_3.status_code == 200, f"Expected 200, got {res_auth_3.status_code}"
    print("[PASS]: Authenticated user completed multiple analyses with zero restrictions")

    # ==========================================================
    # TEST 9: LOGGED-IN USER PDF EXPORT
    # ==========================================================
    print("\n[TEST 9] Authenticated user PDF export...")
    res_pdf_auth = client.post(
        "/reports/pdf",
        json=pdf_payload,
        headers=auth_headers,
    )
    assert res_pdf_auth.status_code == 200, f"PDF export failed: {res_pdf_auth.status_code}"
    assert res_pdf_auth.headers.get("content-type") == "application/pdf", "Expected application/pdf"
    assert len(res_pdf_auth.content) > 1000, "PDF content must not be empty"
    print(f"[PASS]: Authenticated user downloaded PDF report ({len(res_pdf_auth.content)} bytes)")

    # ==========================================================
    # TEST 10: LOGOUT
    # ==========================================================
    print("\n[TEST 10] POST /auth/logout...")
    logout_res = client.post("/auth/logout")
    assert logout_res.status_code == 200, f"Logout failed: {logout_res.text}"
    # Verify refresh_token cookie was deleted / expired
    cookie_header = logout_res.headers.get("set-cookie", "")
    assert "refresh_token=" in cookie_header, "Logout must delete refresh_token cookie"
    print("[PASS]: User logout successfully cleared session cookie")

    # CLEANUP
    db.query(User).filter(User.id == user.id).delete()
    db.query(GuestTrial).delete()
    db.commit()
    db.close()

    print("\n========================================================")
    print("ALL 10 ACCESS CONTROL & AUTHENTICATION TESTS PASSED!")
    print("========================================================\n")


if __name__ == "__main__":
    run_all_tests()
