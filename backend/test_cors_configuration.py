"""
Automated CORS Verification Test for SecureCode AI.
Tests production GitHub Pages origin, localhost development origins,
OPTIONS preflight, registration, login, and rejection of disallowed origins.
"""

import os
import uuid

# Force test DB isolation
os.environ["USE_TEST_DB"] = "1"

from fastapi.testclient import TestClient
from main import app, allowed_origins

client = TestClient(app)

PROD_ORIGIN = "https://buddhadeb-pan.github.io"
LOCAL_5173 = "http://localhost:5173"
IP_5173 = "http://127.0.0.1:5173"
DISALLOWED_ORIGIN = "https://unauthorized-domain.com"


def run_tests():
    print("=" * 60)
    print("TESTING PRODUCTION & LOCAL CORS CONFIGURATION")
    print("=" * 60)

    print(f"\n[Config] Active allowed origins: {allowed_origins}")
    assert PROD_ORIGIN in allowed_origins, f"Production origin {PROD_ORIGIN} not in allowed_origins!"
    assert LOCAL_5173 in allowed_origins, f"Localhost origin {LOCAL_5173} not in allowed_origins!"
    assert IP_5173 in allowed_origins, f"127.0.0.1 origin {IP_5173} not in allowed_origins!"
    print("  [PASS] Allowed origins list contains production and dev origins.")

    # 1. Production OPTIONS preflight on /auth/register
    print(f"\n[Test 1] Production OPTIONS preflight from {PROD_ORIGIN} on /auth/register...")
    res = client.options(
        "/auth/register",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, authorization, x-guest-trial-token",
        },
    )
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert res.headers.get("access-control-allow-origin") == PROD_ORIGIN, f"Wrong allow-origin: {res.headers}"
    assert res.headers.get("access-control-allow-credentials") == "true", f"Credentials not allowed: {res.headers}"
    print("  [PASS] Preflight succeeded with correct Allow-Origin and Allow-Credentials.")

    # 2. Production OPTIONS preflight on /auth/login
    print(f"\n[Test 2] Production OPTIONS preflight from {PROD_ORIGIN} on /auth/login...")
    res = client.options(
        "/auth/login",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert res.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert res.headers.get("access-control-allow-credentials") == "true"
    print("  [PASS] Preflight on /auth/login succeeded.")

    # 3. Production registration request
    unique_email = f"cors_user_{uuid.uuid4().hex[:8]}@example.com"
    print(f"\n[Test 3] Production POST /auth/register from {PROD_ORIGIN}...")
    res = client.post(
        "/auth/register",
        headers={"Origin": PROD_ORIGIN},
        json={
            "name": "Production User",
            "email": unique_email,
            "password": "SecurePassword2026!",
        },
    )
    assert res.status_code == 201, f"Registration failed ({res.status_code}): {res.text}"
    assert res.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert res.headers.get("access-control-allow-credentials") == "true"
    print("  [PASS] Registration succeeded and accepted production origin.")

    # 4. Production login request
    print(f"\n[Test 4] Production POST /auth/login from {PROD_ORIGIN}...")
    res = client.post(
        "/auth/login",
        headers={"Origin": PROD_ORIGIN},
        json={
            "email": unique_email,
            "password": "SecurePassword2026!",
        },
    )
    assert res.status_code == 200, f"Login failed ({res.status_code}): {res.text}"
    assert res.headers.get("access-control-allow-origin") == PROD_ORIGIN
    assert res.headers.get("access-control-allow-credentials") == "true"
    assert "access_token" in res.json(), "access_token missing in response"
    print("  [PASS] Login succeeded and returned access_token with CORS headers.")

    # 5. Localhost (http://localhost:5173) OPTIONS preflight and request
    print(f"\n[Test 5] Development preflight and request from {LOCAL_5173}...")
    res = client.options(
        "/auth/login",
        headers={
            "Origin": LOCAL_5173,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == LOCAL_5173
    assert res.headers.get("access-control-allow-credentials") == "true"

    res = client.post(
        "/auth/login",
        headers={"Origin": LOCAL_5173},
        json={"email": unique_email, "password": "SecurePassword2026!"},
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == LOCAL_5173
    print("  [PASS] http://localhost:5173 preflight and login succeed with credentials.")

    # 6. Localhost IP (http://127.0.0.1:5173) OPTIONS preflight and request
    print(f"\n[Test 6] Development preflight from {IP_5173}...")
    res = client.options(
        "/auth/login",
        headers={
            "Origin": IP_5173,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == IP_5173
    print("  [PASS] http://127.0.0.1:5173 preflight succeeds.")

    # 7. Disallowed origin rejection
    print(f"\n[Test 7] Disallowed origin {DISALLOWED_ORIGIN} rejected...")
    res = client.options(
        "/auth/login",
        headers={
            "Origin": DISALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert res.headers.get("access-control-allow-origin") != DISALLOWED_ORIGIN
    print("  [PASS] Disallowed origin does NOT receive CORS approval header.")

    print("\n" + "=" * 60)
    print("ALL CORS VERIFICATION TESTS PASSED (7/7)!")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
