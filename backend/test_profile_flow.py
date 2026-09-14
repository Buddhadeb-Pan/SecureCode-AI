"""
Automated verification script for profile management and dynamic identity flow.
Validates:
1. Unauthenticated /auth/me access returns 401.
2. User A registers & logs in -> GET /auth/me returns User A dynamic identity.
3. User B registers & logs in -> GET /auth/me returns User B identity without User A residue.
4. PATCH /auth/me updates User A's display name.
5. PATCH /auth/me validates non-empty and trims whitespace.
6. Refreshed GET /auth/me confirms persistence in MySQL.
7. Safe fields only (id, name, email, is_active, created_at) - no passwords/hashes leaked.
"""

import sys
import os

os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db
from database.models import User
from auth.security import hash_password

client = TestClient(app)


def cleanup_user(email: str):
    db = next(get_db())
    try:
        db.query(User).filter(User.email == email).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_profile_flow():
    print("==================================================")
    print("TESTING SECURECODE AI PROFILE & DYNAMIC IDENTITY FLOW")
    print("==================================================")

    user_a_email = "user_a_profile@example.com"
    user_a_name = "Rahul Das"
    user_a_pass = "SecurePass123"

    user_b_email = "user_b_profile@example.com"
    user_b_name = "Priya Sen"
    user_b_pass = "SecurePass456"

    cleanup_user(user_a_email)
    cleanup_user(user_b_email)

    # 1. Unauthenticated /auth/me
    print("\n[Step 1] Checking unauthenticated access to /auth/me...")
    unauth_get = client.get("/auth/me")
    assert unauth_get.status_code == 401, f"Expected 401, got {unauth_get.status_code}"
    unauth_patch = client.patch("/auth/me", json={"name": "Attacker"})
    assert unauth_patch.status_code == 401, f"Expected 401, got {unauth_patch.status_code}"
    print("  [PASS] Unauthenticated access properly rejected with 401")

    # 2. Register & Login User A
    print("\n[Step 2] Registering and logging in User A...")
    reg_a = client.post("/auth/register", json={
        "name": user_a_name,
        "email": user_a_email,
        "password": user_a_pass,
    })
    assert reg_a.status_code == 201, f"User A registration failed: {reg_a.text}"

    login_a = client.post("/auth/login", json={
        "email": user_a_email,
        "password": user_a_pass,
    })
    assert login_a.status_code == 200, f"User A login failed: {login_a.text}"
    token_a = login_a.json()["access_token"]

    # 3. GET /auth/me for User A
    print("\n[Step 3] Verifying GET /auth/me for User A...")
    me_a = client.get("/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me_a.status_code == 200
    data_a = me_a.json()
    assert data_a["name"] == user_a_name, f"Expected {user_a_name}, got {data_a['name']}"
    assert data_a["email"] == user_a_email, f"Expected {user_a_email}, got {data_a['email']}"
    assert data_a["is_active"] is True
    assert "created_at" in data_a
    assert "password" not in data_a and "password_hash" not in data_a
    print(f"  [PASS] User A dynamic identity verified: {data_a['name']} ({data_a['email']})")

    # 4. Register & Login User B
    print("\n[Step 4] Registering and logging in User B...")
    reg_b = client.post("/auth/register", json={
        "name": user_b_name,
        "email": user_b_email,
        "password": user_b_pass,
    })
    assert reg_b.status_code == 201, f"User B registration failed: {reg_b.text}"

    login_b = client.post("/auth/login", json={
        "email": user_b_email,
        "password": user_b_pass,
    })
    assert login_b.status_code == 200, f"User B login failed: {login_b.text}"
    token_b = login_b.json()["access_token"]

    # 5. GET /auth/me for User B
    print("\n[Step 5] Verifying GET /auth/me for User B (Token Isolation & No Residue)...")
    me_b = client.get("/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    assert me_b.status_code == 200
    data_b = me_b.json()
    assert data_b["name"] == user_b_name, f"Expected {user_b_name}, got {data_b['name']}"
    assert data_b["email"] == user_b_email, f"Expected {user_b_email}, got {data_b['email']}"
    assert data_b["email"] != user_a_email, "User A data contaminated User B session!"
    print(f"  [PASS] User B dynamic identity verified: {data_b['name']} ({data_b['email']})")

    # 6. Validation on PATCH /auth/me (Empty/Whitespace Names)
    print("\n[Step 6] Testing validation on PATCH /auth/me...")
    empty_patch = client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"name": "   "}
    )
    assert empty_patch.status_code == 422, f"Expected 422 for whitespace name, got {empty_patch.status_code}"
    print("  [PASS] Empty/whitespace name rejected with 422 Unprocessable Entity")

    # 7. PATCH /auth/me - Update User A name
    new_name = "Rahul K. Das"
    print(f"\n[Step 7] Updating User A name to '{new_name}' via PATCH /auth/me...")
    patch_res = client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"name": f"  {new_name}  "}  # with surrounding whitespace to test trimming
    )
    assert patch_res.status_code == 200, f"PATCH failed: {patch_res.text}"
    patched_data = patch_res.json()
    assert patched_data["name"] == new_name, f"Expected trimmed '{new_name}', got '{patched_data['name']}'"
    assert patched_data["email"] == user_a_email
    print(f"  [PASS] PATCH succeeded: updated name to '{patched_data['name']}'")

    # 8. Verify persistence in MySQL via GET /auth/me
    print("\n[Step 8] Verifying updated name persisted in database via GET /auth/me...")
    re_get = client.get("/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert re_get.status_code == 200
    re_data = re_get.json()
    assert re_data["name"] == new_name
    print(f"  [PASS] Re-query verified persisted name: '{re_data['name']}'")

    # Cleanup
    cleanup_user(user_a_email)
    cleanup_user(user_b_email)

    print("\n==================================================")
    print("ALL PROFILE & DYNAMIC IDENTITY TESTS PASSED (8/8)!")
    print("==================================================")


if __name__ == "__main__":
    test_profile_flow()
