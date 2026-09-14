"""
Automated verification script for Danger Zone Account Deletion flow.
Runs against isolated test DB: securecode_ai_test (USE_TEST_DB=1).

Verifies:
1. Unauthenticated DELETE /auth/me returns 401.
2. User registers and logs in.
3. Deletion attempt with incorrect current password fails with 400.
4. Deletion attempt with invalid confirmation string fails (must be 'DELETE').
5. Valid deletion with correct password and confirmation string succeeds (200).
6. Refresh token cookie is cleared.
7. User is permanently deleted from MySQL users table.
8. PasswordResetToken records for this user are cleaned up.
9. Login with deleted account credentials fails (401).
10. Registration of fresh account with the same email succeeds.
11. Guest trial entitlement and guest records are unaffected.
"""

import os
import sys
import uuid

os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db, get_engine, Base
from database.models import User, PasswordResetToken, GuestTrial
from auth.security import hash_password, create_guest_token

client = TestClient(app)


def cleanup_test_records(email: str, guest_id: str = None):
    db = next(get_db())
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete(synchronize_session=False)
            db.delete(user)
        if guest_id:
            db.query(GuestTrial).filter(GuestTrial.id == guest_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_account_deletion_flow():
    print("==================================================")
    print("TESTING DANGER ZONE ACCOUNT DELETION FLOW (BACKEND)")
    print("==================================================")

    test_email = f"delete_test_{uuid.uuid4().hex[:6]}@example.com"
    test_password = "SecurePassword123"
    guest_id = f"guest_{uuid.uuid4().hex[:8]}"

    cleanup_test_records(test_email, guest_id)

    db = next(get_db())
    # Seed a guest trial to verify guest state isolation
    trial = GuestTrial(id=guest_id, analysis_count=1)
    db.add(trial)
    db.commit()
    db.close()

    # 1. Unauthenticated DELETE /auth/me
    print("\n[Step 1] Checking unauthenticated DELETE /auth/me...")
    unauth_res = client.request(
        "DELETE",
        "/auth/me",
        json={"current_password": test_password, "confirmation": "DELETE"},
    )
    assert unauth_res.status_code == 401, f"Expected 401, got {unauth_res.status_code}"
    print("  [PASS] Unauthenticated DELETE properly rejected with 401")

    # 2. Register and Login
    print("\n[Step 2] Registering and logging in test user...")
    reg_res = client.post("/auth/register", json={
        "name": "Delete Test User",
        "email": test_email,
        "password": test_password,
    })
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"

    login_res = client.post("/auth/login", json={
        "email": test_email,
        "password": test_password,
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    assert "refresh_token" in login_res.cookies, "Expected refresh_token cookie"
    print("  [PASS] User registered and logged in successfully")

    # 3. Create a reset token for this user to test cleanup
    db = next(get_db())
    user_in_db = db.query(User).filter(User.email == test_email).first()
    assert user_in_db is not None
    user_id = user_in_db.id

    from datetime import datetime, timedelta, timezone
    dummy_reset = PasswordResetToken(
        user_id=user_id,
        token_hash="dummy_hash_12345",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),
        used=False,
    )
    db.add(dummy_reset)
    db.commit()
    db.close()

    # 4. Reject wrong password
    print("\n[Step 3] Submitting deletion request with wrong current password...")
    wrong_pwd_res = client.request(
        "DELETE",
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WrongPassword999", "confirmation": "DELETE"},
    )
    assert wrong_pwd_res.status_code == 400, f"Expected 400, got {wrong_pwd_res.status_code}"
    assert wrong_pwd_res.json()["detail"] == "Current password is incorrect."
    # Verify user still exists in DB
    db = next(get_db())
    assert db.query(User).filter(User.id == user_id).first() is not None
    db.close()
    print("  [PASS] Wrong password rejected with 400; account remains intact")

    # 5. Reject invalid confirmation string
    print("\n[Step 4] Submitting deletion request with invalid confirmation string...")
    wrong_confirm_res = client.request(
        "DELETE",
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": test_password, "confirmation": "REMOVE"},
    )
    assert wrong_confirm_res.status_code in (400, 422), f"Expected 400/422, got {wrong_confirm_res.status_code}"
    # Verify user still exists in DB
    db = next(get_db())
    assert db.query(User).filter(User.id == user_id).first() is not None
    db.close()
    print("  [PASS] Invalid confirmation string rejected; account remains intact")

    # 6. Valid deletion
    print("\n[Step 5] Submitting valid account deletion with correct password and 'DELETE'...")
    delete_res = client.request(
        "DELETE",
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": test_password, "confirmation": "DELETE"},
    )
    assert delete_res.status_code == 200, f"Expected 200, got {delete_res.status_code}: {delete_res.text}"
    assert "deleted" in delete_res.json()["message"].lower()
    print("  [PASS] Deletion endpoint returned 200 success")

    # 7. Verify cookie cleared
    cookie_header = delete_res.headers.get("set-cookie", "")
    assert "refresh_token=\"\"" in cookie_header or "refresh_token=;" in cookie_header or "Max-Age=0" in cookie_header
    print("  [PASS] Refresh token cookie cleared")

    # 8. Verify user permanently removed from MySQL
    print("\n[Step 6] Verifying user record permanently deleted from database...")
    db = next(get_db())
    deleted_user = db.query(User).filter(User.id == user_id).first()
    assert deleted_user is None, "User record was NOT removed from MySQL users table!"
    tokens_left = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user_id).count()
    assert tokens_left == 0, f"Reset tokens were not cleaned up, found {tokens_left}"
    db.close()
    print("  [PASS] User permanently purged from MySQL along with related tokens")

    # 9. Verify login fails with deleted credentials
    print("\n[Step 7] Verifying login with deleted credentials fails...")
    failed_login = client.post("/auth/login", json={
        "email": test_email,
        "password": test_password,
    })
    assert failed_login.status_code == 401, f"Expected 401, got {failed_login.status_code}"
    print("  [PASS] Login rejected with 401 for deleted user")

    # 10. Verify re-registration with same email succeeds
    print("\n[Step 8] Verifying new account can be created with the same email...")
    new_reg = client.post("/auth/register", json={
        "name": "Fresh User Same Email",
        "email": test_email,
        "password": "NewBrandPassword456",
    })
    assert new_reg.status_code == 201, f"Re-registration failed: {new_reg.text}"
    print("  [PASS] New user registered cleanly using the deleted email")

    # 11. Verify guest trial entitlement is unchanged
    print("\n[Step 9] Verifying guest trial entitlement isolation...")
    db = next(get_db())
    guest_record = db.query(GuestTrial).filter(GuestTrial.id == guest_id).first()
    assert guest_record is not None, "Guest trial record was corrupted or removed!"
    assert guest_record.analysis_count == 1, "Guest trial count was altered!"
    db.close()
    print("  [PASS] Guest trial count and record completely unaffected by account deletion")

    # Cleanup
    cleanup_test_records(test_email, guest_id)
    print("\n==================================================")
    print("ALL ACCOUNT DELETION TESTS PASSED (11/11)!")
    print("==================================================")


if __name__ == "__main__":
    test_account_deletion_flow()
