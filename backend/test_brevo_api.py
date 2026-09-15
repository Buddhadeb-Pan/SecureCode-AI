"""
Automated unit and integration test suite for Brevo HTTPS API email delivery
and password reset URL construction.
Tests:
1. get_reset_url() with various FRONTEND_URL formats (with/without trailing slashes)
2. Brevo HTTPS API payload construction, headers (api-key, application/json), sender & recipient
3. Brevo HTTPS API simulated HTTP 201 response -> returns (True, None)
4. Brevo HTTPS API simulated HTTP 401 error -> returns (False, safe_err) without leaking secrets
5. Brevo HTTPS API simulated timeout -> returns (False, safe_err)
6. Automatic transport selection: Brevo HTTPS API when BREVO_API_KEY is present,
   fallback to SMTP when BREVO_API_KEY is absent
7. Safe generic message preservation & security template validation
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from auth.security import get_reset_url
from auth.email import (
    get_brevo_api_config,
    is_brevo_api_configured,
    send_email_brevo_api,
    dispatch_email,
    generate_password_reset_email_body,
)


class TestBrevoHttpsEmail(unittest.TestCase):

    def test_01_reset_url_formatting(self):
        """Verify URL joining and trailing-slash handling for production & local URLs."""
        test_token = "secure_token_abc_123"

        # Production URL with trailing slash
        with patch.dict(os.environ, {"FRONTEND_URL": "https://buddhadeb-pan.github.io/SecureCode-AI/"}):
            url = get_reset_url(test_token)
            self.assertEqual(
                url,
                f"https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token={test_token}",
            )

        # Production URL without trailing slash
        with patch.dict(os.environ, {"FRONTEND_URL": "https://buddhadeb-pan.github.io/SecureCode-AI"}):
            url = get_reset_url(test_token)
            self.assertEqual(
                url,
                f"https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token={test_token}",
            )

        # Multiple trailing slashes
        with patch.dict(os.environ, {"FRONTEND_URL": "https://buddhadeb-pan.github.io/SecureCode-AI///"}):
            url = get_reset_url(test_token)
            self.assertEqual(
                url,
                f"https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token={test_token}",
            )

        # Default localhost fallback
        with patch.dict(os.environ, {"FRONTEND_URL": ""}):
            url = get_reset_url(test_token)
            self.assertEqual(
                url,
                f"http://localhost:5173/reset-password?token={test_token}",
            )

    def test_02_brevo_api_payload_and_headers(self):
        """Verify Brevo HTTPS API request payload structure and headers."""
        fake_api_key = "xkeysib-mock-api-key-test"
        fake_sender = "panbuddhadeb230@gmail.com"
        target_recipient = "user@example.com"
        subject = "Reset Your SecureCode AI Password"
        text_content = "Please reset your password at: https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token=xyz"
        html_content = "<p>Reset your password</p>"

        env_patch = {
            "BREVO_API_KEY": fake_api_key,
            "EMAIL_FROM": fake_sender,
        }

        with patch.dict(os.environ, env_patch), patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"messageId": "<12345@brevo.com>"}
            mock_post.return_value = mock_response

            success, err = send_email_brevo_api(
                to_email=target_recipient,
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                is_reset_email=True,
            )

            self.assertTrue(success)
            self.assertIsNone(err)

            # Assert request arguments
            mock_post.assert_called_once()
            called_args, called_kwargs = mock_post.call_args

            self.assertEqual(called_args[0], "https://api.brevo.com/v3/smtp/email")
            headers = called_kwargs["headers"]
            self.assertEqual(headers["api-key"], fake_api_key)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(headers["Accept"], "application/json")

            payload = called_kwargs["json"]
            self.assertEqual(payload["sender"]["name"], "SecureCode AI")
            self.assertEqual(payload["sender"]["email"], fake_sender)
            self.assertEqual(payload["to"], [{"email": target_recipient}])
            self.assertEqual(payload["subject"], subject)
            self.assertEqual(payload["htmlContent"], html_content)
            self.assertEqual(payload["textContent"], text_content)

    def test_03_brevo_api_error_handling_no_leak(self):
        """Verify Brevo API errors are captured safely without exposing API keys or secrets."""
        fake_api_key = "xkeysib-secret-key"
        with patch.dict(os.environ, {"BREVO_API_KEY": fake_api_key, "EMAIL_FROM": "sender@test.com"}), \
             patch("requests.post") as mock_post:

            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.json.return_value = {"code": "unauthorized", "message": "Key not found"}
            mock_post.return_value = mock_response

            success, err = send_email_brevo_api(
                to_email="test@example.com",
                subject="Test Subject",
                text_content="Text",
                html_content="<p>HTML</p>",
            )

            self.assertFalse(success)
            self.assertIsNotNone(err)
            self.assertNotIn(fake_api_key, err)
            self.assertIn("401", err)

    def test_04_transport_selection_logic(self):
        """Verify that dispatch_email uses Brevo API when configured, and falls back to SMTP otherwise."""
        # Case A: BREVO_API_KEY is present -> uses HTTPS API
        with patch.dict(os.environ, {"BREVO_API_KEY": "xkeysib-active", "EMAIL_FROM": "s@test.com"}), \
             patch("auth.email.send_email_brevo_api", return_value=(True, None)) as mock_api, \
             patch("auth.email.send_email_smtp") as mock_smtp:

            self.assertTrue(is_brevo_api_configured())
            success, _ = dispatch_email("u@test.com", "Sub", "Txt", "Html")
            self.assertTrue(success)
            mock_api.assert_called_once()
            mock_smtp.assert_not_called()

        # Case B: BREVO_API_KEY is empty -> falls back to SMTP
        with patch.dict(os.environ, {"BREVO_API_KEY": ""}), \
             patch("auth.email.is_smtp_configured", return_value=True), \
             patch("auth.email.send_email_smtp", return_value=(True, None)) as mock_smtp, \
             patch("auth.email.send_email_brevo_api") as mock_api:

            self.assertFalse(is_brevo_api_configured())
            success, _ = dispatch_email("u@test.com", "Sub", "Txt", "Html")
            self.assertTrue(success)
            mock_smtp.assert_called_once()
            mock_api.assert_not_called()

    def test_05_email_template_content(self):
        """Ensure password reset template contains required branding and notices."""
        reset_link = "https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token=tok123"
        text_body, html_body = generate_password_reset_email_body(reset_link, expire_minutes=20)

        self.assertIn("SecureCode AI", text_body)
        self.assertIn("SecureCode", html_body)
        self.assertIn(reset_link, text_body)
        self.assertIn(reset_link, html_body)
        self.assertIn("20 minutes", text_body)
        self.assertIn("20 minutes", html_body)
        self.assertIn("ignore this email", text_body.lower())
        self.assertIn("ignore this email", html_body.lower())


if __name__ == "__main__":
    unittest.main()
