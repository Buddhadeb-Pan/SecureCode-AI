"""
Automated test suite for SecureCode AI user registration flow.
Tests endpoint POST /auth/register, Argon2 hashing, database insertion,
duplicate detection, validation errors, and response safety.
"""

import sys
import os
import time

# ISOLATE AUTOMATED TEST DATA: Strictly target securecode_ai_test
os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db, get_engine
from database.models import User
from auth.security import verify_password


client = TestClient(app)


def test_user_registration():
    print("==================================================")
    print("TESTING SECURECODE AI USER REGISTRATION FLOW (ISOLATED TEST DB)")
    print("==================================================")

    engine = get_engine()
    test_email = f"test_{int(time.time())}@example.com"
    test_password = "TestPassword123"
    test_name = "Test User"

    # Clean up any leftover test user in test DB
    db = next(get_db())
    try:
        db.query(User).filter(User.email.in_([test_email, "test@example.com"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    # 1. TEST REGISTRATION WITH VALID DATA
    print("\n[Step 1] Sending POST /auth/register with valid payload...")
    payload = {
        "name": test_name,
        "email": test_email,
        "password": test_password,
    }
    response = client.post("/auth/register", json=payload)
    print(f"  -> HTTP Status: {response.status_code}")
    assert response.status_code == 201, f"Expected 201 Created, got {response.status_code}: {response.text}"

    data = response.json()
    print(f"  -> Response JSON: {data}")

    # Verify no password leaks in response
    assert "password" not in data, "Plain password leaked in response!"
    assert "password_hash" not in data, "Password hash leaked in response!"
    assert data["name"] == test_name
    assert data["email"] == test_email.lower()
    assert data["is_active"] is True
    assert "id" in data and "created_at" in data
    print("  [PASS] Response returned valid, safe UserResponse without sensitive fields.")

    # 2. VERIFY ROW IN MYSQL TEST DATABASE
    print("\n[Step 2] Verifying MySQL test database record...")
    db = next(get_db())
    try:
        user_in_db = db.query(User).filter(User.email == test_email.lower()).first()
        assert user_in_db is not None, "User row was not found in test database!"
        print(f"  -> User found in test DB with ID: {user_in_db.id}")
        print(f"  -> Stored name: {user_in_db.name}")
        print(f"  -> Stored email: {user_in_db.email}")
        print(f"  -> Password hash prefix: {user_in_db.password_hash[:20]}...")

        # Assert Argon2 hashing
        assert user_in_db.password_hash.startswith("$argon2"), f"Hash does not start with $argon2: {user_in_db.password_hash}"
        assert test_password not in user_in_db.password_hash, "Plain password found in password_hash!"

        # Assert verify_password works
        assert verify_password(test_password, user_in_db.password_hash), "Argon2 verification failed for stored hash!"
        assert not verify_password("WrongPassword123", user_in_db.password_hash), "Argon2 verified wrong password!"
        print("  [PASS] Stored password is verified as valid Argon2id hash. Plain password is NOT stored.")
    finally:
        db.close()

    # 3. TEST DUPLICATE EMAIL REJECTION (HTTP 409)
    print("\n[Step 3] Testing duplicate email registration rejection...")
    dup_response = client.post("/auth/register", json=payload)
    print(f"  -> HTTP Status: {dup_response.status_code}")
    assert dup_response.status_code == 409, f"Expected 409 Conflict, got {dup_response.status_code}"
    print(f"  -> Detail message: {dup_response.json().get('detail')}")
    assert "already registered" in dup_response.json().get("detail", "").lower()
    print("  [PASS] Duplicate registration successfully rejected with HTTP 409.")

    # 4. TEST PASSWORD VALIDATION POLICY (< 8 characters, whitespace, letters-only, numbers-only)
    print("\n[Step 4] Testing password policy validation rules...")
    
    # 4a: Short password (< 8 chars)
    short_pw_resp = client.post("/auth/register", json={
        "name": "Short Pass User",
        "email": f"short_{int(time.time())}@example.com",
        "password": "short",
    })
    assert short_pw_resp.status_code == 422, f"Expected 422 for short password, got {short_pw_resp.status_code}"
    print("  [PASS] Short password (< 8 chars) correctly rejected with HTTP 422.")

    # 4b: Whitespace-only password
    empty_pw_resp = client.post("/auth/register", json={
        "name": "Empty Pass User",
        "email": f"empty_{int(time.time())}@example.com",
        "password": "        ",
    })
    assert empty_pw_resp.status_code == 422, f"Expected 422 for empty password, got {empty_pw_resp.status_code}"
    print("  [PASS] Whitespace-only password correctly rejected with HTTP 422.")

    # 4c: Letters-only password (no number)
    letters_only_resp = client.post("/auth/register", json={
        "name": "Letter Only User",
        "email": f"letters_{int(time.time())}@example.com",
        "password": "LettersOnlyPassword",
    })
    assert letters_only_resp.status_code == 422, f"Expected 422 for letters-only, got {letters_only_resp.status_code}"
    print("  [PASS] Letters-only password correctly rejected with HTTP 422.")

    # 4d: Numbers-only password (no letter)
    numbers_only_resp = client.post("/auth/register", json={
        "name": "Numbers Only User",
        "email": f"numbers_{int(time.time())}@example.com",
        "password": "1234567890123",
    })
    assert numbers_only_resp.status_code == 422, f"Expected 422 for numbers-only, got {numbers_only_resp.status_code}"
    print("  [PASS] Numbers-only password correctly rejected with HTTP 422.")

    # 5. TEST REAL EXAMPLE REGISTRATION: Rahul Das / rahuldas@gmail.com
    print("\n[Step 5] Testing realistic registration: Rahul Das / rahuldas_test@example.com...")
    real_payload = {
        "name": "Rahul Das",
        "email": "rahuldas_test@example.com",
        "password": "RahulPassword123",
    }
    db = next(get_db())
    try:
        db.query(User).filter(User.email == real_payload["email"]).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    real_resp = client.post("/auth/register", json=real_payload)
    print(f"  -> HTTP Status: {real_resp.status_code}")
    assert real_resp.status_code == 201, f"Expected 201, got {real_resp.status_code}"
    real_data = real_resp.json()
    assert real_data["name"] == "Rahul Das"
    assert real_data["email"] == "rahuldas_test@example.com"
    print("  [PASS] Realistic user saved with exact name and normalized email.")

    print("\n==================================================")
    print("ALL REGISTRATION FLOW TESTS PASSED IN ISOLATED TEST DB!")
    print("==================================================")


if __name__ == "__main__":
    test_user_registration()
