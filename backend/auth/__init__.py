"""
Authentication module for SecureCode AI.
Exports registration, login & password reset schemas, Argon2 security utilities, JWT helpers, and auth router.
"""

from .schemas import (
    RegisterRequest,
    UserResponse,
    LoginRequest,
    TokenResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)
from .security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    get_jwt_algorithm,
    get_access_token_expire_minutes,
    generate_reset_token,
    hash_reset_token,
    get_reset_url,
    RESET_TOKEN_EXPIRE_MINUTES,
)
from .email import (
    send_password_reset_email,
    send_test_email,
    get_smtp_config,
    is_smtp_configured,
)
from .routes import router as auth_router

__all__ = [
    "RegisterRequest",
    "UserResponse",
    "LoginRequest",
    "TokenResponse",
    "ForgotPasswordRequest",
    "ForgotPasswordResponse",
    "ResetPasswordRequest",
    "ResetPasswordResponse",
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "get_jwt_algorithm",
    "get_access_token_expire_minutes",
    "generate_reset_token",
    "hash_reset_token",
    "get_reset_url",
    "RESET_TOKEN_EXPIRE_MINUTES",
    "send_password_reset_email",
    "send_test_email",
    "get_smtp_config",
    "is_smtp_configured",
    "auth_router",
]

