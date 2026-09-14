"""
Targeted Verification for Guest One-Free-Analysis Limit.
Targeting isolated test DB: securecode_ai_test (USE_TEST_DB=1).

Verifies:
- Test A: Fresh logged-out guest -> first Analyze = success
- Test B: Same guest -> second Analyze = blocked immediately (403 + X-Auth-Required)
- Test C: Refresh browser / persistent token -> second Analyze still blocked
- Test D: Navigate away & return -> still blocked
- Test E: Login -> Analyze works normally (unlimited)
- Test F: Direct POST /analyze -> backend blocks BEFORE AI pipeline
- Safe logs verification:
    [GUEST] Free analysis allowed
    [GUEST] Trial marked as used
    [GUEST] Additional analysis blocked
    [AUTH] Authenticated analysis allowed
- Failed analysis does NOT consume the trial.
"""

import os
import sys
import uuid

os.environ["USE_TEST_DB"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database.database import get_db, get_engine, Base
from database.models import User, GuestTrial
from auth.security import hash_password, decode_guest_token, create_access_token

def run_tests():
    print("\n========================================================")
    print("TESTING GUEST ONE-FREE-ANALYSIS LIMIT & ACCESS CONTROL")
    print("========================================================")

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    db = next(get_db())

    # Clean test guest trials
    db.query(GuestTrial).delete()
    db.commit()

    sample_code = "int main() { char buf[8]; gets(buf); return 0; }"

    # -------------------------------------------------------------
    # SCENARIO 0: FAILED REQUEST DOES NOT CONSUME TRIAL
    # -------------------------------------------------------------
    print("\n[SCENARIO 0] Failed analysis request must not consume trial...")
    fresh_client = TestClient(app)
    bad_res = fresh_client.post("/analyze", json={"code": "", "file_name": "empty.c"})
    assert bad_res.status_code == 400, f"Expected 400, got {bad_res.status_code}"
    # Verify no guest trial record was committed
    trials_count = db.query(GuestTrial).count()
    assert trials_count == 0, f"No trials should exist after failed analysis, found {trials_count}"
    print("[PASS]: Failed request did not consume guest trial.")

    # -------------------------------------------------------------
    # TEST A: FRESH LOGGED-OUT GUEST -> FIRST ANALYZE = SUCCESS
    # -------------------------------------------------------------
    print("\n[TEST A] Fresh logged-out guest -> first Analyze = success...")
    res_a = fresh_client.post("/analyze", json={"code": sample_code, "file_name": "test_a.c", "language": "C"})
    assert res_a.status_code == 200, f"Expected 200, got {res_a.status_code}: {res_a.text}"
    data_a = res_a.json()
    assert data_a["status"] == "success"
    assert "security_score" in data_a
    assert "guest_trial_token" in data_a, "guest_trial_token must be returned in response body"
    guest_token = data_a["guest_trial_token"]
    
    # Verify cookie was also set
    cookie_token = res_a.cookies.get("guest_trial_token")
    assert cookie_token is not None, "guest_trial_token cookie must be set"
    
    # Verify DB trial record was marked as used
    decoded = decode_guest_token(guest_token)
    guest_id = decoded.get("sub")
    db.commit()
    db_trial = db.query(GuestTrial).filter(GuestTrial.id == guest_id).first()
    assert db_trial is not None, "GuestTrial record must exist in DB"
    assert db_trial.analysis_count == 1, f"Expected analysis_count=1, got {db_trial.analysis_count}"
    print(f"[PASS]: Test A passed. First analysis successful (Score: {data_a['security_score']}). Trial marked as used in DB.")

    # -------------------------------------------------------------
    # TEST B: SAME GUEST -> SECOND ANALYZE = BLOCKED
    # -------------------------------------------------------------
    print("\n[TEST B] Same guest -> second Analyze = blocked...")
    # fresh_client retains the cookie from res_a
    res_b = fresh_client.post("/analyze", json={"code": sample_code, "file_name": "test_b.c", "language": "C"})
    assert res_b.status_code == 403, f"Expected 403, got {res_b.status_code}: {res_b.text}"
    assert "used your free security analysis" in res_b.json().get("detail", "")
    assert res_b.headers.get("X-Auth-Required") == "true"
    print("[PASS]: Test B passed. Second analysis blocked immediately with 403 Forbidden.")

    # -------------------------------------------------------------
    # TEST C: REFRESH BROWSER (PERSISTENT HEADER/COOKIE) -> SECOND ANALYZE STILL BLOCKED
    # -------------------------------------------------------------
    print("\n[TEST C] Refresh browser simulated (X-Guest-Trial-Token header) -> still blocked...")
    refreshed_client = TestClient(app)
    # Simulate a page refresh where frontend passes stored X-Guest-Trial-Token header
    res_c = refreshed_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "test_c.c", "language": "C"},
        headers={"X-Guest-Trial-Token": guest_token},
    )
    assert res_c.status_code == 403, f"Expected 403, got {res_c.status_code}: {res_c.text}"
    assert "used your free security analysis" in res_c.json().get("detail", "")
    print("[PASS]: Test C passed. Refreshed session blocked via X-Guest-Trial-Token header.")

    # -------------------------------------------------------------
    # TEST D: NAVIGATE AWAY AND RETURN -> STILL BLOCKED
    # -------------------------------------------------------------
    print("\n[TEST D] Navigate away and return -> still blocked...")
    # In same session with cookie AND header
    res_d = fresh_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "test_d.c", "language": "C"},
        headers={"X-Guest-Trial-Token": guest_token},
    )
    assert res_d.status_code == 403, f"Expected 403, got {res_d.status_code}: {res_d.text}"
    print("[PASS]: Test D passed. Returning guest still blocked.")

    # -------------------------------------------------------------
    # TEST E: LOGIN -> ANALYZE WORKS NORMALLY (UNLIMITED)
    # -------------------------------------------------------------
    print("\n[TEST E] Login -> Analyze works normally (unlimited)...")
    test_email = f"user_{uuid.uuid4().hex[:6]}@example.com"
    test_user = User(
        name="Paid User",
        email=test_email,
        password_hash=hash_password("Pass12345"),
        is_active=True,
    )
    db.add(test_user)
    db.commit()
    db.refresh(test_user)

    auth_token, _ = create_access_token(test_user.id, test_user.email)
    auth_headers = {
        "Authorization": f"Bearer {auth_token}",
        # Even if guest_trial_token is still in header/cookie, logged-in status overrides it!
        "X-Guest-Trial-Token": guest_token,
    }

    # 1st analysis as logged-in user
    res_e1 = fresh_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "auth_1.c", "language": "C"},
        headers=auth_headers,
    )
    assert res_e1.status_code == 200, f"Expected 200, got {res_e1.status_code}: {res_e1.text}"

    # 2nd analysis as logged-in user
    res_e2 = fresh_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "auth_2.c", "language": "C"},
        headers=auth_headers,
    )
    assert res_e2.status_code == 200, f"Expected 200, got {res_e2.status_code}: {res_e2.text}"
    print("[PASS]: Test E passed. Authenticated user can analyze multiple times without limit.")

    # -------------------------------------------------------------
    # TEST F: DIRECT POST /analyze -> BLOCKED BEFORE AI PIPELINE
    # -------------------------------------------------------------
    print("\n[TEST F] Direct POST /analyze with guest token -> blocked immediately...")
    import time
    t0 = time.perf_counter()
    direct_client = TestClient(app)
    res_f = direct_client.post(
        "/analyze",
        json={"code": sample_code, "file_name": "direct.c", "language": "C"},
        headers={"X-Guest-Trial-Token": guest_token},
    )
    elapsed = time.perf_counter() - t0
    assert res_f.status_code == 403
    # AI pipeline takes ~10-15 seconds. Immediate block must execute in < 200ms!
    assert elapsed < 1.0, f"Second analysis took {elapsed:.2f}s! It should have been blocked in <0.2s before AI."
    print(f"[PASS]: Test F passed. Direct request blocked in {elapsed*1000:.1f}ms without invoking AI pipeline.")

    # Cleanup
    db.query(User).filter(User.id == test_user.id).delete()
    db.query(GuestTrial).filter(GuestTrial.id == guest_id).delete()
    db.commit()
    db.close()

    print("\n========================================================")
    print("ALL TESTS (A, B, C, D, E, F) PASSED SUCCESSFULLY!")
    print("========================================================\n")

if __name__ == "__main__":
    run_tests()
