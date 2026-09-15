"""
Email utility for SecureCode AI.
Handles Brevo SMTP email delivery for password reset flows using STARTTLS on port 587.
Credentials are read dynamically from environment variables and never logged or hardcoded.
"""

import os
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple, Optional, Dict, Any
import requests
from dotenv import load_dotenv

# Ensure backend/.env can be located and reloaded dynamically
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def get_smtp_config() -> Dict[str, Any]:
    """
    Dynamically retrieves Brevo SMTP configuration from environment.
    Never hardcodes or exposes sensitive credentials.
    """
    if os.path.exists(_ENV_PATH):
        load_dotenv(dotenv_path=_ENV_PATH, override=True)
    else:
        load_dotenv(override=True)

    host = os.getenv("SMTP_HOST", "smtp-relay.brevo.com").strip()
    port_raw = os.getenv("SMTP_PORT", "587").strip()
    try:
        port = int(port_raw)
    except (ValueError, TypeError):
        port = 587

    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    email_from = os.getenv("EMAIL_FROM", "").strip()

    if not email_from:
        email_from = username if ("@" in username) else "no-reply@securecode.ai"

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "from": email_from,
    }


def is_smtp_configured() -> bool:
    """
    Returns True if the required SMTP settings (host, port, username, password) are populated.
    """
    config = get_smtp_config()
    return bool(config["host"] and config["port"] and config["username"] and config["password"])


def get_brevo_api_config() -> Dict[str, Any]:
    """
    Dynamically retrieves Brevo HTTPS API configuration from environment.
    Never hardcodes or exposes sensitive credentials.
    """
    if os.path.exists(_ENV_PATH):
        load_dotenv(dotenv_path=_ENV_PATH, override=True)
    else:
        load_dotenv(override=True)

    api_key = os.getenv("BREVO_API_KEY", "").strip()
    email_from = os.getenv("EMAIL_FROM", "").strip()

    if not email_from:
        smtp_user = os.getenv("SMTP_USERNAME", "").strip()
        email_from = smtp_user if ("@" in smtp_user) else "no-reply@securecode.ai"

    return {
        "api_key": api_key,
        "from": email_from,
    }


def is_brevo_api_configured() -> bool:
    """
    Returns True if BREVO_API_KEY is populated.
    """
    config = get_brevo_api_config()
    return bool(config["api_key"])


def send_email_brevo_api(
    to_email: str,
    subject: str,
    text_content: str,
    html_content: str,
    is_reset_email: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Sends an email via Brevo HTTPS Transactional Email API (POST https://api.brevo.com/v3/smtp/email).
    Bypasses outbound SMTP port 587 blocking on Render Free.
    Safely logs diagnostic messages without exposing API keys or tokens.

    Returns:
        (success: bool, error_message: Optional[str])
    """
    config = get_brevo_api_config()
    api_key = config["api_key"]
    email_from = config["from"]

    if not api_key:
        safe_msg = "Brevo API key is not configured"
        print(f"[EMAIL ERROR] {safe_msg}")
        return False, safe_msg

    if not email_from:
        safe_msg = "EMAIL_FROM is not configured in environment"
        print(f"[EMAIL ERROR] {safe_msg}")
        return False, safe_msg

    print("[EMAIL] Brevo HTTPS API configuration loaded")
    if is_reset_email:
        print("[EMAIL] Sending reset email via Brevo HTTPS API to registered user")
    else:
        print("[EMAIL] Sending test email via Brevo HTTPS API")

    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "sender": {
            "name": "SecureCode AI",
            "email": email_from,
        },
        "to": [
            {
                "email": to_email,
            }
        ],
        "subject": subject,
        "htmlContent": html_content,
        "textContent": text_content,
    }

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers=headers,
            json=payload,
            timeout=10,
        )

        if 200 <= response.status_code < 300:
            if is_reset_email:
                print("[EMAIL] Reset email sent successfully via Brevo HTTPS API")
            else:
                print("[EMAIL] Test email sent successfully via Brevo HTTPS API")
            return True, None
        else:
            safe_detail = f"status {response.status_code}"
            try:
                err_data = response.json()
                if isinstance(err_data, dict) and "message" in err_data:
                    safe_detail += f": {err_data['message']}"
            except Exception:
                pass
            safe_err = f"Brevo HTTPS API delivery failure ({safe_detail})"
            print(f"[EMAIL ERROR] {safe_err}")
            return False, safe_err

    except requests.exceptions.Timeout:
        safe_err = "Brevo API request timed out"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err
    except requests.exceptions.RequestException as req_err:
        safe_err = f"Brevo API connection failure: {type(req_err).__name__}"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err
    except Exception as err:
        safe_err = f"Brevo API delivery error: {type(err).__name__}"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err


def mask_email(email: str) -> str:
    """Safely masks an email address for non-sensitive logging (e.g. u***@example.com)."""
    if not email or "@" not in email:
        return "***"
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        masked_name = name[0] + "***" if name else "***"
    else:
        masked_name = name[0] + "***" + name[-1]
    return f"{masked_name}@{domain}"


def generate_password_reset_email_body(reset_url: str, expire_minutes: int = 20) -> Tuple[str, str]:
    """
    Generates plain-text and responsive HTML email templates for SecureCode AI password reset.
    Includes branding, reset message, reset link, and clear expiration notice.
    """
    text_content = (
        f"SecureCode AI — Password Reset Request\n\n"
        f"Hello,\n\n"
        f"We received a request to reset your password for your SecureCode AI account.\n\n"
        f"Please click or paste the following link in your browser to choose a new password:\n"
        f"{reset_url}\n\n"
        f"IMPORTANT SECURITY NOTICE:\n"
        f"- This password reset link expires in {expire_minutes} minutes.\n"
        f"- This link can only be used once.\n"
        f"- If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged.\n\n"
        f"Best regards,\n"
        f"SecureCode AI Security Team\n"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Your SecureCode AI Password</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0; -webkit-font-smoothing: antialiased;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #0b0f19; width: 100%; min-height: 100vh; padding: 40px 15px;">
    <tr>
      <td align="center" valign="top">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 540px; background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
          
          <!-- Header -->
          <tr>
            <td style="padding: 32px 32px 24px 32px; background: linear-gradient(180deg, #162032 0%, #111827 100%); border-bottom: 1px solid #1f2937;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td style="vertical-align: middle;">
                    <div style="font-size: 22px; font-weight: 700; color: #f8fafc; letter-spacing: -0.5px;">
                      <span style="color: #06b6d4;">🛡️ SecureCode</span> AI
                    </div>
                    <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">
                      Automated Security & Vulnerability Analysis Platform
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td style="padding: 32px;">
              <h1 style="margin: 0 0 16px 0; font-size: 20px; font-weight: 600; color: #f1f5f9;">
                Password Reset Request
              </h1>
              
              <p style="margin: 0 0 16px 0; font-size: 14px; line-height: 1.6; color: #cbd5e1;">
                Hello,
              </p>
              
              <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.6; color: #cbd5e1;">
                We received a request to reset your password for your <strong>SecureCode AI</strong> account. Click the button below to set a new, secure password:
              </p>

              <!-- Action Button -->
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 28px 0;">
                <tr>
                  <td align="center" style="border-radius: 8px; background: linear-gradient(135deg, #06b6d4 0%, #0284c7 100%);">
                    <a href="{reset_url}" target="_blank" style="display: inline-block; padding: 12px 28px; font-size: 14px; font-weight: 600; color: #0b0f19; text-decoration: none; border-radius: 8px;">
                      Reset Password
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Expiry Alert -->
              <div style="background-color: rgba(6, 182, 212, 0.08); border-left: 4px solid #06b6d4; padding: 12px 16px; border-radius: 4px; margin: 24px 0;">
                <p style="margin: 0; font-size: 13px; color: #67e8f9; line-height: 1.5;">
                  ⏱️ <strong>Security Notice:</strong> This password reset link expires in <strong>{expire_minutes} minutes</strong> and can only be used once.
                </p>
              </div>

              <!-- Fallback URL -->
              <p style="margin: 24px 0 8px 0; font-size: 12px; color: #94a3b8; line-height: 1.5;">
                If the button above does not work, copy and paste this link into your browser:
              </p>
              <p style="margin: 0 0 24px 0; font-size: 12px; color: #38bdf8; word-break: break-all; line-height: 1.4;">
                <a href="{reset_url}" style="color: #38bdf8; text-decoration: underline;">{reset_url}</a>
              </p>

              <hr style="border: none; border-top: 1px solid #1f2937; margin: 24px 0;" />

              <!-- Security Disclaimer -->
              <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
                If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged and your account is secure.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 20px 32px; background-color: #0d131f; border-top: 1px solid #1f2937; text-align: center;">
              <p style="margin: 0; font-size: 11px; color: #64748b;">
                © 2026 SecureCode AI. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return text_content, html_content


def send_email_smtp(
    to_email: str,
    subject: str,
    text_content: str,
    html_content: str,
    is_reset_email: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Sends an email via Brevo SMTP using STARTTLS on port 587.
    Safely logs required status messages and captures errors without logging passwords or secrets.
    
    Returns:
        (success: bool, error_message: Optional[str])
    """
    config = get_smtp_config()
    host = config["host"]
    port = config["port"]
    username = config["username"]
    password = config["password"]
    email_from = config["from"]

    if not username or not password:
        safe_msg = "authentication failure: SMTP credentials (username/password) are not set in environment"
        print(f"[EMAIL ERROR] {safe_msg}")
        return False, safe_msg

    print("[EMAIL] SMTP configuration loaded")

    if is_reset_email:
        print("[EMAIL] Sending reset email to registered user")
    else:
        print("[EMAIL] Sending test email")

    # Build MIME message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f"SecureCode AI <{email_from}>"
    message["To"] = to_email

    # Plain text and HTML parts
    part_text = MIMEText(text_content, "plain", "utf-8")
    part_html = MIMEText(html_content, "html", "utf-8")
    message.attach(part_text)
    message.attach(part_html)

    # Dispatch via Brevo SMTP with STARTTLS on port 587
    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception as tls_err:
                safe_err = f"TLS failure: {type(tls_err).__name__}"
                print(f"[EMAIL ERROR] {safe_err}")
                return False, safe_err

            try:
                server.login(username, password)
                print("[EMAIL] SMTP authentication successful")
            except smtplib.SMTPAuthenticationError as auth_err:
                safe_err = f"authentication failure: invalid credentials (code: {getattr(auth_err, 'smtp_code', '535')})"
                print(f"[EMAIL ERROR] {safe_err}")
                return False, safe_err

            try:
                server.sendmail(email_from, [to_email], message.as_string())
                if is_reset_email:
                    print("[EMAIL] Reset email sent successfully")
                else:
                    print("[EMAIL] Test email sent successfully")
                return True, None
            except smtplib.SMTPSenderRefused as sender_err:
                safe_err = f"sender rejected: sender {mask_email(email_from)} not authorized"
                print(f"[EMAIL ERROR] {safe_err}")
                return False, safe_err
            except smtplib.SMTPRecipientsRefused:
                safe_err = f"recipient rejected: address {mask_email(to_email)} refused by host"
                print(f"[EMAIL ERROR] {safe_err}")
                return False, safe_err

    except (TimeoutError, socket.timeout):
        safe_err = "connection timeout: timed out connecting to SMTP host"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err
    except (ConnectionRefusedError, smtplib.SMTPConnectError):
        safe_err = f"connection failure: could not connect to {host}:{port}"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err
    except Exception as err:
        safe_err = f"SMTP delivery failure: {type(err).__name__}"
        print(f"[EMAIL ERROR] {safe_err}")
        return False, safe_err


def dispatch_email(
    to_email: str,
    subject: str,
    text_content: str,
    html_content: str,
    is_reset_email: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Unified email dispatcher.
    Prioritizes Brevo HTTPS API (required for Render Free production where SMTP is blocked).
    Falls back cleanly to Brevo SMTP for local development if BREVO_API_KEY is not set.
    """
    if is_brevo_api_configured():
        return send_email_brevo_api(
            to_email=to_email,
            subject=subject,
            text_content=text_content,
            html_content=html_content,
            is_reset_email=is_reset_email,
        )
    elif is_smtp_configured():
        print("[EMAIL] BREVO_API_KEY not configured; falling back to local Brevo SMTP transport")
        return send_email_smtp(
            to_email=to_email,
            subject=subject,
            text_content=text_content,
            html_content=html_content,
            is_reset_email=is_reset_email,
        )
    else:
        safe_msg = "No email provider configured (neither BREVO_API_KEY nor SMTP credentials found)"
        print(f"[EMAIL ERROR] {safe_msg}")
        return False, safe_msg


def send_password_reset_email(
    to_email: str,
    reset_url: str,
    expire_minutes: int = 20,
) -> Tuple[bool, Optional[str]]:
    """
    Prepares and dispatches a branded password reset email to the specified user email.
    Uses Brevo HTTPS API in production, falling back to Brevo SMTP locally.
    Never crashes caller; returns (success, error_message).
    """
    subject = "Reset Your SecureCode AI Password"
    text_body, html_body = generate_password_reset_email_body(
        reset_url=reset_url,
        expire_minutes=expire_minutes,
    )
    return dispatch_email(
        to_email=to_email,
        subject=subject,
        text_content=text_body,
        html_content=html_body,
        is_reset_email=True,
    )


def send_test_email(to_email: str) -> Tuple[bool, Optional[str]]:
    """
    Sends a test verification email to confirm email delivery via Brevo HTTPS API or SMTP.
    """
    subject = "SecureCode AI — Brevo Delivery Test"
    text_content = (
        "Hello,\n\n"
        "This is a test email sent from SecureCode AI via Brevo.\n"
        "If you received this message, your Brevo email delivery configuration is operating properly!\n\n"
        "Best regards,\n"
        "SecureCode AI Security Team\n"
    )
    html_content = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Delivery Test</title></head>
<body style="margin:0;padding:24px;background-color:#0b0f19;font-family:sans-serif;color:#e2e8f0;">
  <div style="max-width:500px;margin:auto;background-color:#111827;border:1px solid #1f2937;border-radius:8px;padding:24px;">
    <h2 style="color:#06b6d4;margin-top:0;">🛡️ SecureCode AI — Brevo Delivery Test</h2>
    <p>This email verifies that your <strong>Brevo</strong> email integration is operational.</p>
    <div style="background:rgba(6,182,212,0.1);border-left:4px solid #06b6d4;padding:10px 14px;margin:16px 0;color:#67e8f9;font-size:13px;border-radius:4px;">
      ✅ Connection &amp; Authentication Successful
    </div>
    <p style="font-size:12px;color:#64748b;margin-top:20px;">SecureCode AI Platform • Automated Security Testing</p>
  </div>
</body>
</html>"""
    return dispatch_email(
        to_email=to_email,
        subject=subject,
        text_content=text_content,
        html_content=html_content,
        is_reset_email=False,
    )

