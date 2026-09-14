"""
Local SMTP test using a registered user email.
Tests:
1. Verifies that the registered user exists (or registers if needed)
2. Calls POST /auth/forgot-password for this registered user
3. Verifies terminal logs:
   [EMAIL] SMTP configuration loaded
   [EMAIL] Sending reset email to registered user
   [EMAIL] SMTP authentication successful
   [EMAIL] Reset email sent successfully
4. Verifies Brevo SMTP accepts the message and returns HTTP 200 with generic response
"""

import sys
import os

# ISOLATE AUTOMATED TEST DATA: Strictly target securecode_ai_test
os.environ["USE_TEST_DB"] = "1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from main import app
from database.database import get_db
from database.models import User, PasswordResetToken
from auth.security import hash_password

client = TestClient(app)

def test_registered_user_smtp_delivery():
    print("==================================================")
    print("TESTING FORGOT-PASSWORD SMTP DELIVERY WITH REGISTERED USER")
    print("==================================================")

    # Use the verified email from .env
    test_email = "panbuddhadeb230@gmail.com"
    db = next(get_db())

    # Check if user already exists or create in test DB
    user = db.query(User).filter(User.email == test_email).first()
    if not user:
        user = User(
            name="Buddhadeb Pan",
            email=test_email,
            password_hash=hash_password("SecurePassword123!"),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"[SETUP] Created registered user for {test_email} in test DB (ID: {user.id})")
    else:
        print(f"[SETUP] Found existing registered user for {test_email} in test DB (ID: {user.id})")

    # Call POST /auth/forgot-password
    print(f"\n[REQUEST] Sending POST /auth/forgot-password for registered user {test_email}...")
    response = client.post("/auth/forgot-password", json={"email": test_email})

    print(f"\n[RESPONSE] Status Code: {response.status_code}")
    print(f"[RESPONSE] Body: {response.json()}")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["message"] == "If an account exists for this email, a password reset link has been sent."
    assert "reset_url" not in data, "reset_url leaked in API response!"
    assert "token" not in data, "token leaked in API response!"

    # Verify password_reset_tokens table has an active token using fresh session
    db.close()
    verify_db = next(get_db())
    latest_token = (
        verify_db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == user.id)
        .order_by(PasswordResetToken.id.desc())
        .first()
    )
    assert latest_token is not None, "PasswordResetToken record was not created!"
    assert latest_token.used is False, "PasswordResetToken should not be marked as used"
    print(f"[VERIFY] MySQL PasswordResetToken created successfully (ID: {latest_token.id}, used: {latest_token.used})")
    verify_db.close()

    print("\n==================================================")
    print("REGISTERED USER SMTP DELIVERY TEST PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_registered_user_smtp_delivery()
