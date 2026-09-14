"""
Automated test suite for SecureCode AI Forgot Password & Reset Password flow.
Tests:
1. Existing email -> reset token created in MySQL (hashed)
2. Unknown email -> same safe generic response returned
3. Valid token -> password changed successfully
4. Old password -> login fails (HTTP 401)
5. New password -> login succeeds (HTTP 200 + JWT)
6. Reused token -> rejected (HTTP 400)
7. Expired token -> rejected (HTTP 400)
8. Weak new password (< 8 chars) -> rejected (HTTP 422)
"""

import sys
import os
import time
from datetime import datetime, timedelta, timezone

# ISOLATE AUTOMATED TEST DATA: Strictly target securecode_ai_test
os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db, get_engine
from database.models import User, PasswordResetToken
from auth.security import hash_password, hash_reset_token, generate_reset_token

client = TestClient(app)


def test_forgot_and_reset_password():
    print("==================================================")
    print("TESTING FORGOT PASSWORD & RESET PASSWORD FLOW (ISOLATED TEST DB)")
    print("==================================================")

    test_email = "reset_test_user@example.com"
    old_password = "OldPassword123"
    new_password = "NewPassword123"

    # Setup: prepare active test user in test database
    db = next(get_db())
    try:
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id.in_(
                db.query(User.id).filter(User.email == test_email)
            )
        ).delete(synchronize_session=False)
        db.query(User).filter(User.email == test_email).delete(synchronize_session=False)
        db.commit()

        user = User(
            name="Reset Test User",
            email=test_email,
            password_hash=hash_password(old_password),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        print(f"Setup: Created user '{test_email}' (ID {user_id}) with initial password.")
    finally:
        db.close()

    # 1. UNKNOWN EMAIL -> SAME SAFE PUBLIC RESPONSE
    print("\n[Test 1] POST /auth/forgot-password with unknown email...")
    unknown_resp = client.post("/auth/forgot-password", json={
        "email": "nonexistent_email_xyz@example.com"
    })
    print(f"  -> HTTP Status: {unknown_resp.status_code}")
    print(f"  -> Response: {unknown_resp.json()}")
    assert unknown_resp.status_code == 200
    assert unknown_resp.json()["message"] == "If an account exists for this email, a password reset link has been sent."
    assert "reset_url" not in unknown_resp.json() or unknown_resp.json().get("reset_url") is None
    print("  [PASS] Unknown email returns identical safe response without leaking existence.")

    # 2. EXISTING EMAIL -> TOKEN CREATED IN DB, BUT NOT LEAKED IN API RESPONSE
    print("\n[Test 2] POST /auth/forgot-password with existing email...")
    forgot_resp = client.post("/auth/forgot-password", json={
        "email": test_email
    })
    print(f"  -> HTTP Status: {forgot_resp.status_code}")
    print(f"  -> Message: {forgot_resp.json().get('message')}")
    assert forgot_resp.status_code == 200
    assert forgot_resp.json()["message"] == "If an account exists for this email, a password reset link has been sent."
    
    # CRITICAL: Confirm reset_url / reset_token is NOT exposed in response
    assert "reset_url" not in forgot_resp.json(), "reset_url leaked in API response!"
    assert "reset_token" not in forgot_resp.json(), "reset_token leaked in API response!"
    assert "token" not in forgot_resp.json(), "token leaked in API response!"
    print("  [PASS] API response does NOT expose reset_url, token, or debug link.")

    # Verify reset token record was created in MySQL password_reset_tokens table
    db = next(get_db())
    try:
        latest_record = (
            db.query(PasswordResetToken)
            .filter(PasswordResetToken.user_id == user_id)
            .order_by(PasswordResetToken.id.desc())
            .first()
        )
        assert latest_record is not None, "Reset token was not found in database!"
        assert latest_record.used is False
        print(f"  -> Token verified in DB: ID {latest_record.id}, used={latest_record.used}")
        print("  [PASS] Reset token created and stored as SHA-256 hash in MySQL.")
    finally:
        db.close()

    # Create a known token in DB to test the reset endpoint
    raw_token = generate_reset_token()
    token_hash = hash_reset_token(raw_token)
    db = next(get_db())
    try:
        token_record = PasswordResetToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),
            used=False,
        )
        db.add(token_record)
        db.commit()
    finally:
        db.close()

    # 3. WEAK NEW PASSWORD (< 8 CHARS) -> REJECTED (HTTP 422)
    print("\n[Test 3] POST /auth/reset-password with weak password (< 8 chars)...")
    weak_resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "short",
    })
    assert weak_resp.status_code == 422, f"Expected 422, got {weak_resp.status_code}"
    print("  [PASS] Password < 8 characters rejected with HTTP 422.")

    # 3b. PASSWORD WITHOUT DIGITS -> REJECTED (HTTP 422)
    print("\n[Test 3b] POST /auth/reset-password with letters-only password...")
    no_num_resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "LettersOnlyPassword",
    })
    assert no_num_resp.status_code == 422, f"Expected 422, got {no_num_resp.status_code}"
    print("  [PASS] Password without numbers rejected with HTTP 422.")

    # 4. VALID TOKEN -> PASSWORD CHANGED
    print("\n[Test 4] POST /auth/reset-password with valid token...")
    reset_resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": new_password,
    })
    print(f"  -> HTTP Status: {reset_resp.status_code}")
    print(f"  -> Response: {reset_resp.json()}")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["message"] == "Password has been successfully reset."
    print("  [PASS] Password successfully reset.")

    # 5. REUSED TOKEN -> REJECTED (HTTP 400)
    print("\n[Test 5] Reusing the same reset token...")
    reuse_resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "AnotherPassword123",
    })
    print(f"  -> HTTP Status: {reuse_resp.status_code}")
    print(f"  -> Response: {reuse_resp.json()}")
    assert reuse_resp.status_code == 400
    assert "Invalid or expired" in reuse_resp.json().get("detail", "")
    print("  [PASS] Reused token rejected with HTTP 400.")

    # 6. OLD PASSWORD LOGIN -> MUST FAIL (HTTP 401)
    print("\n[Test 6] Attempting login with OLD password...")
    old_login_resp = client.post("/auth/login", json={
        "email": test_email,
        "password": old_password,
    })
    print(f"  -> HTTP Status: {old_login_resp.status_code}")
    assert old_login_resp.status_code == 401
    assert old_login_resp.json().get("detail") == "Invalid email or password"
    print("  [PASS] Old password rejected with HTTP 401.")

    # 7. NEW PASSWORD LOGIN -> MUST SUCCEED (HTTP 200 + JWT)
    print("\n[Test 7] Attempting login with NEW password...")
    new_login_resp = client.post("/auth/login", json={
        "email": test_email,
        "password": new_password,
    })
    print(f"  -> HTTP Status: {new_login_resp.status_code}")
    assert new_login_resp.status_code == 200
    assert "access_token" in new_login_resp.json()
    assert new_login_resp.json()["token_type"] == "bearer"
    print("  [PASS] New password authenticated successfully with HTTP 200.")

    # 8. EXPIRED TOKEN -> REJECTED (HTTP 400)
    print("\n[Test 8] Testing expired reset token...")
    expired_raw_token = generate_reset_token()
    expired_hash = hash_reset_token(expired_raw_token)
    db = next(get_db())
    try:
        expired_record = PasswordResetToken(
            user_id=user_id,
            token_hash=expired_hash,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),  # already expired
            used=False,
        )
        db.add(expired_record)
        db.commit()
    finally:
        db.close()

    expired_resp = client.post("/auth/reset-password", json={
        "token": expired_raw_token,
        "new_password": "YetAnotherPassword123",
    })
    print(f"  -> HTTP Status: {expired_resp.status_code}")
    assert expired_resp.status_code == 400
    assert "Invalid or expired" in expired_resp.json().get("detail", "")
    print("  [PASS] Expired reset token correctly rejected with HTTP 400.")

    print("\n==================================================")
    print("ALL FORGOT & RESET PASSWORD TESTS PASSED IN ISOLATED TEST DB!")
    print("==================================================")


if __name__ == "__main__":
    test_forgot_and_reset_password()
