"""
Automated test suite for SecureCode AI Login and JWT authentication flow.
Tests POST /auth/login:
- Correct email + correct password -> 200 + valid JWT
- Correct email + wrong password -> 401
- Unknown email -> 401
- Inactive user -> 401
- JWT claims local verification (sub, email, exp, iat, no sensitive leaks)
"""

import sys
import os
import time
from datetime import datetime, timezone

# ISOLATE AUTOMATED TEST DATA: Strictly target securecode_ai_test
os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db
from database.models import User
from auth.security import hash_password, decode_access_token, get_jwt_algorithm, get_access_token_expire_minutes

client = TestClient(app)


def test_login_flow():
    print("==================================================")
    print("TESTING SECURECODE AI LOGIN + JWT AUTHENTICATION (ISOLATED TEST DB)")
    print("==================================================")

    test_email = "testuser@example.com"
    test_password = "TestPassword123"
    inactive_email = "inactive_user@example.com"

    # Setup: prepare test users in test database
    db = next(get_db())
    try:
        # Clean up existing test accounts in test DB
        db.query(User).filter(User.email.in_([test_email, inactive_email])).delete(synchronize_session=False)
        db.commit()

        # Insert active test user with Argon2 hash
        active_user = User(
            name="Test User",
            email=test_email,
            password_hash=hash_password(test_password),
            is_active=True,
        )
        db.add(active_user)

        # Insert inactive test user with Argon2 hash
        inactive_user = User(
            name="Inactive User",
            email=inactive_email,
            password_hash=hash_password(test_password),
            is_active=False,
        )
        db.add(inactive_user)

        db.commit()
        db.refresh(active_user)
        db.refresh(inactive_user)
        active_user_id = active_user.id
        print(f"Setup: Created active user '{test_email}' (ID {active_user_id}) and inactive user '{inactive_email}'")
    finally:
        db.close()

    # 1. TEST CORRECT EMAIL + CORRECT PASSWORD -> HTTP 200
    print("\n[Test 1] Correct email + correct password...")
    payload = {
        "email": test_email,
        "password": test_password,
    }
    response = client.post("/auth/login", json=payload)
    print(f"  -> HTTP Status: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    print(f"  -> Token Type: {data.get('token_type')}")
    print(f"  -> Expires In (seconds): {data.get('expires_in')}")
    print(f"  -> Access Token (truncated): {data.get('access_token')[:25]}...")

    assert "access_token" in data and len(data["access_token"]) > 20
    assert data["token_type"] == "bearer"
    assert data.get("expires_in") == 3600
    assert "password" not in data
    assert "password_hash" not in data
    print("  [PASS] Successfully logged in and received TokenResponse.")

    # 2. LOCAL JWT CLAIMS VERIFICATION (Without external calls)
    print("\n[Test 2] Local JWT token verification & claims validation...")
    token = data["access_token"]
    decoded = decode_access_token(token)
    print(f"  -> Decoded claims: {decoded}")

    assert "sub" in decoded, "Claim 'sub' is missing in JWT"
    assert decoded["sub"] == str(active_user_id), f"Expected sub={active_user_id}, got {decoded['sub']}"
    assert "email" in decoded, "Claim 'email' is missing in JWT"
    assert decoded["email"] == test_email
    assert "exp" in decoded, "Claim 'exp' is missing in JWT"
    assert "iat" in decoded, "Claim 'iat' is missing in JWT"

    # Verify no leaks in claims
    assert "password" not in decoded
    assert "password_hash" not in decoded

    # Verify expiration timestamp is in the future
    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp_ts = decoded["exp"]
    assert exp_ts > now_ts, "JWT expiration is not in the future"
    diff_minutes = (exp_ts - now_ts) // 60
    assert 58 <= diff_minutes <= 60, f"Expected ~60 minute expiry, got {diff_minutes} minutes"
    print(f"  -> Token expires in: ~{diff_minutes} minutes")
    print(f"  -> Algorithm used: {get_jwt_algorithm()}")
    print("  [PASS] Local JWT decoding verified all required claims and validity.")

    # 3. TEST CORRECT EMAIL + WRONG PASSWORD -> HTTP 401
    print("\n[Test 3] Correct email + wrong password...")
    wrong_pw_resp = client.post("/auth/login", json={
        "email": test_email,
        "password": "WrongPassword999",
    })
    print(f"  -> HTTP Status: {wrong_pw_resp.status_code}")
    print(f"  -> Error detail: {wrong_pw_resp.json().get('detail')}")
    assert wrong_pw_resp.status_code == 401, f"Expected 401, got {wrong_pw_resp.status_code}"
    assert wrong_pw_resp.json().get("detail") == "Invalid email or password"
    print("  [PASS] Wrong password rejected with HTTP 401 'Invalid email or password'.")

    # 3b. TEST RANDOM PASSWORD -> HTTP 401
    print("\n[Test 3b] Correct email + completely random password...")
    random_pw_resp = client.post("/auth/login", json={
        "email": test_email,
        "password": "kjsdhf78234@#$randomPassword_xyz",
    })
    print(f"  -> HTTP Status: {random_pw_resp.status_code}")
    assert random_pw_resp.status_code == 401, f"Expected 401, got {random_pw_resp.status_code}"
    assert random_pw_resp.json().get("detail") == "Invalid email or password"
    print("  [PASS] Random password rejected with HTTP 401 'Invalid email or password'.")

    # 4. TEST UNKNOWN EMAIL -> HTTP 401
    print("\n[Test 4] Unknown email address...")
    unknown_resp = client.post("/auth/login", json={
        "email": "nonexistent_user_xyz@example.com",
        "password": test_password,
    })
    print(f"  -> HTTP Status: {unknown_resp.status_code}")
    print(f"  -> Error detail: {unknown_resp.json().get('detail')}")
    assert unknown_resp.status_code == 401, f"Expected 401, got {unknown_resp.status_code}"
    assert unknown_resp.json().get("detail") == "Invalid email or password"
    print("  [PASS] Unknown email rejected with identical HTTP 401 'Invalid email or password'.")

    # 5. TEST INACTIVE USER -> REJECT LOGIN
    print("\n[Test 5] Inactive user account login...")
    inactive_resp = client.post("/auth/login", json={
        "email": inactive_email,
        "password": test_password,
    })
    print(f"  -> HTTP Status: {inactive_resp.status_code}")
    print(f"  -> Error detail: {inactive_resp.json().get('detail')}")
    assert inactive_resp.status_code == 401, f"Expected 401, got {inactive_resp.status_code}"
    assert inactive_resp.json().get("detail") == "Invalid email or password"
    print("  [PASS] Inactive user rejected with HTTP 401.")

    # 6. TEST EMAIL CASE NORMALIZATION
    print("\n[Test 6] Email case normalization (TESTUSER@EXAMPLE.COM)...")
    caps_resp = client.post("/auth/login", json={
        "email": "TESTUSER@EXAMPLE.COM",
        "password": test_password,
    })
    assert caps_resp.status_code == 200, f"Expected 200 for uppercase email, got {caps_resp.status_code}"
    print("  [PASS] Email normalized and authenticated successfully.")

    # 7. VERIFY REGISTRATION ENDPOINT WITH PASSWORD COMPLEXITY
    print("\n[Test 7] Verify /auth/register remains fully functional with password policy...")
    reg_email = f"test_login_reg_{int(time.time())}@example.com"
    reg_resp = client.post("/auth/register", json={
        "name": "Another User",
        "email": reg_email,
        "password": "ValidPassword123",
    })
    assert reg_resp.status_code == 201
    assert reg_resp.json()["email"] == reg_email
    print("  [PASS] Existing /auth/register verified working without changes in test DB.")

    print("\n==================================================")
    print("ALL LOGIN & JWT TESTS PASSED SUCCESSFULLY IN ISOLATED TEST DB!")
    print("==================================================")


if __name__ == "__main__":
    test_login_flow()
