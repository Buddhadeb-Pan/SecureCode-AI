"""
Automated verification script for Settings Change Password flow.
Tests:
1. Unauthenticated POST /auth/change-password returns 401.
2. User registers and logs in.
3. Wrong current password returns 400 ("Current password is incorrect.").
4. Weak new password returns 422.
5. Valid password change returns 200 and success message.
6. Login with old password fails (401).
7. Login with new password succeeds (200).
8. Dynamic profile retrieval (GET /auth/me) works with updated account.
"""

import sys
import os

os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db
from database.models import User

client = TestClient(app)


def cleanup_user(email: str):
    db = next(get_db())
    try:
        db.query(User).filter(User.email == email).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_change_password_flow():
    print("==================================================")
    print("TESTING SETTINGS CHANGE PASSWORD FLOW (BACKEND)")
    print("==================================================")

    test_email = "settings_test_user@example.com"
    initial_pass = "InitialPass123"
    updated_pass = "UpdatedPass456"

    cleanup_user(test_email)

    # 1. Unauthenticated access
    print("\n[Step 1] Checking unauthenticated POST /auth/change-password...")
    res = client.post("/auth/change-password", json={
        "current_password": initial_pass,
        "new_password": updated_pass,
    })
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print("  [PASS] Unauthenticated change-password rejected with 401")

    # 2. Register and login
    print("\n[Step 2] Registering and logging in user...")
    reg = client.post("/auth/register", json={
        "name": "Settings Test User",
        "email": test_email,
        "password": initial_pass,
    })
    assert reg.status_code == 201

    login = client.post("/auth/login", json={
        "email": test_email,
        "password": initial_pass,
    })
    assert login.status_code == 200
    token = login.json()["access_token"]
    print("  [PASS] User registered and logged in successfully")

    # 3. Wrong current password
    print("\n[Step 3] Submitting wrong current password...")
    wrong_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "WrongPassword999",
            "new_password": updated_pass,
        }
    )
    assert wrong_res.status_code == 400
    err_data = wrong_res.json()
    assert err_data["detail"] == "Current password is incorrect."
    print("  [PASS] Rejected with 400 'Current password is incorrect.'")

    # 4. Weak new password (no number or < 8 chars)
    print("\n[Step 4] Submitting weak new password (letters only)...")
    weak_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": initial_pass,
            "new_password": "alllettersonly",
        }
    )
    assert weak_res.status_code == 422
    print("  [PASS] Weak password rejected with 422 validation error")

    # 5. Successful password update
    print("\n[Step 5] Submitting valid password change...")
    success_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": initial_pass,
            "new_password": updated_pass,
        }
    )
    assert success_res.status_code == 200
    success_data = success_res.json()
    assert success_data["message"] == "Password has been successfully updated."
    print("  [PASS] Password successfully updated")

    # 6. Verify OLD password no longer works
    print("\n[Step 6] Verifying old password fails at /auth/login...")
    old_login = client.post("/auth/login", json={
        "email": test_email,
        "password": initial_pass,
    })
    assert old_login.status_code == 401
    print("  [PASS] Old password rejected with 401")

    # 7. Verify NEW password works at /auth/login
    print("\n[Step 7] Verifying new password succeeds at /auth/login...")
    new_login = client.post("/auth/login", json={
        "email": test_email,
        "password": updated_pass,
    })
    assert new_login.status_code == 200
    new_token = new_login.json()["access_token"]
    print("  [PASS] New password accepted, new session issued")

    # 8. Verify GET /auth/me works with new session
    print("\n[Step 8] Verifying GET /auth/me with new session...")
    me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == test_email
    print("  [PASS] GET /auth/me returned correct dynamic identity")

    cleanup_user(test_email)
    print("\n==================================================")
    print("ALL SETTINGS CHANGE PASSWORD TESTS PASSED (8/8)!")
    print("==================================================")


if __name__ == "__main__":
    test_change_password_flow()
