"""
Verification script for frontend Forgot Password & Reset Password integration flow.
Simulates the exact HTTP requests and browser steps performed by the React frontend.
"""

import sys
import os
import urllib.parse
from datetime import datetime, timedelta, timezone

# ISOLATE AUTOMATED TEST DATA: Strictly target securecode_ai_test
os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db
from database.models import User, PasswordResetToken
from auth.security import hash_password, generate_reset_token, hash_reset_token

client = TestClient(app)


def verify_frontend_auth_flow():
    print("==================================================")
    print("TESTING FRONTEND -> BACKEND FORGOT & RESET FLOW (ISOLATED TEST DB)")
    print("==================================================")

    test_email = "frontend_flow_user@example.com"
    initial_password = "InitialPassword123"
    updated_password = "BrandNewPassword999"

    # Setup user in test database
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
            name="Frontend Flow User",
            email=test_email,
            password_hash=hash_password(initial_password),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        print(f"Setup: Created test user '{test_email}' (ID {user_id})")
    finally:
        db.close()

    # Step 1: User on /forgot-password sends email
    print("\n[Step 1] Submitting email on /forgot-password...")
    forgot_res = client.post("/auth/forgot-password", json={"email": test_email})
    assert forgot_res.status_code == 200
    forgot_data = forgot_res.json()
    print(f"  -> Response message: {forgot_data['message']}")
    assert forgot_data["message"] == "If an account exists for this email, a password reset link has been sent."
    
    # CRITICAL SECURITY CHECK: API response must NOT expose reset_url or token
    assert "reset_url" not in forgot_data, "reset_url leaked in response!"
    assert "token" not in forgot_data, "token leaked in response!"
    print("  [PASS] API response does NOT expose reset_url or reset token to the browser.")

    # Step 2: Simulate token delivered via email
    # Generate and record a valid token in test DB to simulate the link clicked from email
    token = generate_reset_token()
    db = next(get_db())
    try:
        token_record = PasswordResetToken(
            user_id=user_id,
            token_hash=hash_reset_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),
            used=False,
        )
        db.add(token_record)
        db.commit()
    finally:
        db.close()
    print(f"  -> User received email with link /reset-password?token={token[:12]}...")

    # Step 3: User submits new password on /reset-password
    print("\n[Step 2] Submitting new password on /reset-password...")
    reset_res = client.post("/auth/reset-password", json={
        "token": token,
        "new_password": updated_password,
    })
    assert reset_res.status_code == 200
    reset_data = reset_res.json()
    print(f"  -> Reset response: {reset_data['message']}")
    assert reset_data["message"] == "Password has been successfully reset."

    # Step 4: Verify OLD password fails on /login
    print("\n[Step 3] Verifying OLD password fails on /login...")
    old_login_res = client.post("/auth/login", json={
        "email": test_email,
        "password": initial_password,
    })
    print(f"  -> Status code with old password: {old_login_res.status_code}")
    assert old_login_res.status_code == 401
    assert old_login_res.json()["detail"] == "Invalid email or password"
    print("  [PASS] Old password correctly rejected.")

    # Step 5: Verify NEW password succeeds on /login
    print("\n[Step 4] Verifying NEW password succeeds on /login...")
    new_login_res = client.post("/auth/login", json={
        "email": test_email,
        "password": updated_password,
    })
    print(f"  -> Status code with new password: {new_login_res.status_code}")
    assert new_login_res.status_code == 200
    new_login_data = new_login_res.json()
    assert "access_token" in new_login_data
    assert new_login_data["token_type"] == "bearer"
    print("  [PASS] New password authenticated and issued valid JWT.")

    # Step 6: Verify reused token is rejected
    print("\n[Step 5] Verifying token cannot be reused...")
    reuse_res = client.post("/auth/reset-password", json={
        "token": token,
        "new_password": "YetAnotherPassword123",
    })
    print(f"  -> Reused token status code: {reuse_res.status_code}")
    assert reuse_res.status_code == 400
    print("  [PASS] Reused token rejected with HTTP 400.")

    # Step 7: Verify unknown email returns identical safe response
    print("\n[Step 6] Verifying unknown email returns safe response...")
    unknown_res = client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    assert unknown_res.status_code == 200
    assert "reset_url" not in unknown_res.json()
    print("  [PASS] Unknown email safely handled without account enumeration.")

    print("\n==================================================")
    print("ALL FRONTEND INTEGRATION FLOW TESTS PASSED!")
    print("==================================================")


if __name__ == "__main__":
    verify_frontend_auth_flow()
