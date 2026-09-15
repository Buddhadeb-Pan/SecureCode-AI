"""
Password security and JWT utilities for SecureCode AI.
Implements Argon2id password hashing and secure JWT access token generation/verification.
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, Dict, Any
from dotenv import load_dotenv
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Ensure backend/.env is located reliably
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if os.path.exists(env_path):
    load_dotenv(dotenv_path=env_path, override=True)
else:
    load_dotenv(override=True)

# Thread-safe Argon2id hasher using standard recommended memory and time costs
_hasher = PasswordHasher()


# =========================================================
# ARGON2 PASSWORD HASHING & VERIFICATION
# =========================================================

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using the Argon2id algorithm.
    Never stores or returns plaintext passwords.
    """
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2 hash string.
    Uses Argon2's internal constant-time verification.
    Never re-hashes incoming password for manual string comparison.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# =========================================================
# JWT CONFIGURATION & HELPERS
# =========================================================

def get_jwt_secret_key() -> str:
    """
    Retrieves the JWT signing secret key from the environment.
    Fails with a clear RuntimeError if missing, never falling back to insecure defaults.
    """
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret or not secret.strip():
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not configured. "
            "Please set JWT_SECRET_KEY in your .env file."
        )
    return secret.strip()


def get_jwt_algorithm() -> str:
    """Returns the JWT signature algorithm (default: HS256)."""
    return os.getenv("JWT_ALGORITHM", "HS256").strip()


def get_access_token_expire_minutes() -> int:
    """Returns access token expiration duration in minutes (default: 60)."""
    try:
        return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    except ValueError:
        return 60


def get_refresh_token_expire_days() -> int:
    """Returns refresh token expiration duration in days (default: 7)."""
    try:
        return int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    except ValueError:
        return 7


def is_production_environment() -> bool:
    """Returns True if the application is running in production mode."""
    return os.getenv("ENVIRONMENT", "").strip().lower() in ("production", "prod")


def get_refresh_cookie_settings() -> Dict[str, Any]:
    """
    Returns environment-aware cookie configuration for refresh tokens.
    Localhost / development: secure=False to allow plain HTTP development.
    Production: secure=True over HTTPS.
    Always enforces httponly=True, samesite='lax', path='/'.
    """
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": is_production_environment(),
        "path": "/",
    }


def create_access_token(
    user_id: int,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, int]:
    """
    Generates a signed JWT access token containing only minimal safe claims:
    - sub (subject / user id as string)
    - email (user email)
    - type ("access")
    - iat (issued at timestamp)
    - exp (expiration timestamp)
    Does NOT include passwords, hashes, API keys, or sensitive personal data.

    Returns:
        (access_token, expires_in_seconds)
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()

    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
        expires_in = int(expires_delta.total_seconds())
    else:
        minutes = get_access_token_expire_minutes()
        expire = now + timedelta(minutes=minutes)
        expires_in = minutes * 60

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token, expires_in


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token locally.
    Verifies signature, expiration, and ensures type == 'access'.
    Raises jwt.PyJWTError on failure.
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()
    payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Invalid token type: expected access token")
    return payload


def create_refresh_token(
    user_id: int,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, int]:
    """
    Generates a signed JWT refresh token for session renewal:
    - sub (subject / user id as string)
    - type ("refresh")
    - iat (issued at timestamp)
    - exp (expiration timestamp)

    Returns:
        (refresh_token, expires_in_seconds)
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()

    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
        expires_in = int(expires_delta.total_seconds())
    else:
        days = get_refresh_token_expire_days()
        expire = now + timedelta(days=days)
        expires_in = days * 86400

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token, expires_in


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT refresh token locally.
    Verifies signature, expiration, and ensures type == 'refresh'.
    Raises jwt.PyJWTError on failure.
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()
    payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    if payload.get("type") != "refresh":
        raise jwt.InvalidTokenError("Invalid token type: expected refresh token")
    return payload


def create_guest_token(guest_id: str, days: int = 365) -> str:
    """
    Generates a cryptographically signed guest trial token.
    Contains guest_id in 'sub' and type='guest'.
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()

    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=days)

    payload: Dict[str, Any] = {
        "sub": guest_id,
        "type": "guest",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_guest_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a guest trial token.
    Raises jwt.PyJWTError on failure.
    """
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()
    payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    if payload.get("type") != "guest":
        raise jwt.InvalidTokenError("Invalid token type: expected guest token")
    return payload


# =========================================================
# PASSWORD RESET TOKEN UTILITIES (20 MINUTE EXPIRY)
# =========================================================

RESET_TOKEN_EXPIRE_MINUTES = 20


def generate_reset_token() -> str:
    """
    Generates a cryptographically secure random token for password resets.
    Does NOT use the standard access JWT.
    """
    return secrets.token_urlsafe(32)


def hash_reset_token(raw_token: str) -> str:
    """
    Hashes a raw reset token using SHA-256 for safe database storage.
    Prevents token exposure even in the event of database compromise.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_reset_url(raw_token: str) -> str:
    """
    Constructs the frontend password reset URL for production and local environments.
    Handles trailing slashes and whitespace in FRONTEND_URL cleanly.
    Expected production format:
    https://buddhadeb-pan.github.io/SecureCode-AI/reset-password?token=<token>
    """
    base_url = (os.getenv("FRONTEND_URL") or "http://localhost:5173").strip().rstrip("/")
    if not base_url:
        base_url = "http://localhost:5173"
    token_param = (raw_token or "").strip()
    return f"{base_url}/reset-password?token={token_param}"

