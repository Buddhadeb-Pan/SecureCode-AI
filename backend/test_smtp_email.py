"""
Simple local test script for Brevo SMTP email delivery in SecureCode AI.
Tests:
1. Dynamic loading of SMTP configuration from backend/.env
2. Brevo SMTP connection using STARTTLS on port 587
3. Masked credential verification (never logs plain passwords or secrets)
4. Password reset template content validation (branding, link, 20-minute expiry)
5. Test email dispatch to a specified or default recipient address

Usage:
    python test_smtp_email.py [optional_recipient_email]
"""

import sys
import os

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from auth.email import (
    get_smtp_config,
    is_smtp_configured,
    send_test_email,
    generate_password_reset_email_body,
    mask_email,
)


def run_smtp_test():
    print("==================================================")
    print("SECURECODE AI - BREVO SMTP VERIFICATION TEST")
    print("==================================================")

    # 1. Inspect Environment Configuration
    config = get_smtp_config()
    host = config["host"]
    port = config["port"]
    username = config["username"]
    password = config["password"]
    email_from = config["from"]

    print(f"\n[1] Checking Brevo SMTP Configuration from .env:")
    print(f"    - Host        : {host}")
    print(f"    - Port        : {port} (STARTTLS)")
    print(f"    - Username    : {mask_email(username) if username else 'NOT SET'}")
    print(f"    - Password    : {'****** [Configured]' if password else 'NOT SET'}")
    print(f"    - From Email  : {mask_email(email_from) if email_from else 'NOT SET'}")

    # 2. Validate Password Reset Template Content
    print(f"\n[2] Validating Password Reset Email Template:")
    sample_reset_url = "http://localhost:5173/reset-password?token=sample_test_token_12345"
    text_body, html_body = generate_password_reset_email_body(sample_reset_url, expire_minutes=20)

    assert "SecureCode AI" in text_body, "Text template missing SecureCode AI branding"
    assert "SecureCode AI" in html_body, "HTML template missing SecureCode AI branding"
    assert sample_reset_url in text_body, "Text template missing reset link"
    assert sample_reset_url in html_body, "HTML template missing reset link"
    assert "20 minutes" in text_body, "Text template missing 20-minute expiry notice"
    assert "20 minutes" in html_body, "HTML template missing 20-minute expiry notice"
    print("    [PASS] Template contains SecureCode AI branding, reset URL, and 20-minute expiry notice.")

    # 3. Determine Test Target Email
    if len(sys.argv) > 1 and "@" in sys.argv[1]:
        test_recipient = sys.argv[1].strip()
    elif username and "@" in username:
        test_recipient = username
    elif email_from and "@" in email_from and not email_from.startswith("no-reply@"):
        test_recipient = email_from
    else:
        test_recipient = "test@securecode.ai"

    print(f"\n[3] Target Test Email Address:")
    print(f"    - Recipient   : {test_recipient}")

    # 4. Connection & Delivery Test
    print(f"\n[4] Attempting Brevo SMTP Delivery:")
    if not is_smtp_configured():
        print("    [INFO] SMTP credentials are not yet configured in backend/.env.")
        print("    Please ensure the following variables are saved in backend/.env:")
        print("        SMTP_HOST=smtp-relay.brevo.com")
        print("        SMTP_PORT=587")
        print("        SMTP_USERNAME=your_brevo_account_login")
        print("        SMTP_PASSWORD=your_brevo_smtp_key")
        print("        EMAIL_FROM=your_verified_sender_email")
        print("\n    Note: Password reset endpoint handles missing or failed SMTP gracefully")
        print("    without crashing the server or exposing credentials.")
        return False

    success, err_message = send_test_email(test_recipient)
    if success:
        print(f"    [SUCCESS] Test email was dispatched successfully via Brevo SMTP to {mask_email(test_recipient)}!")
        return True
    else:
        print(f"    [FAILURE] SMTP delivery failed: {err_message}")
        print("    Verify your Brevo account status, SMTP credentials, and authorized sender.")
        return False


if __name__ == "__main__":
    success = run_smtp_test()
    print("\n==================================================")
    print(f"RESULT: {'SMTP TEST PASSED' if success else 'SMTP TEST FINISHED (Check configuration)'}")
    print("==================================================")
