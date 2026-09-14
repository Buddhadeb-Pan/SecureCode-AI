"""
Pydantic schemas for authentication and user management.
Validates registration input and defines safe output models.
"""

import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


def validate_password_complexity(password: str) -> str:
    """
    Enforces a reasonable professional password policy:
    - Minimum 8 characters
    - Maximum 128 characters
    - At least one letter
    - At least one number
    - Rejects empty or whitespace-only password
    """
    if not password or not password.strip():
        raise ValueError("Password cannot be empty or whitespace only.")
    if len(password) < 8 or len(password) > 128:
        raise ValueError("Password must be between 8 and 128 characters long.")
    if not re.search(r"[a-zA-Z]", password):
        raise ValueError("Password must contain at least one letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number.")
    return password


class RegisterRequest(BaseModel):
    """
    Registration request payload.
    Enforces password complexity (8-128 chars, letter + number) and non-empty name.
    """
    name: str = Field(..., min_length=1, max_length=255, description="Full name")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password (minimum 8 characters)")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty or whitespace only.")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class UserResponse(BaseModel):
    """
    Safe public response schema for user accounts.
    Explicitly excludes sensitive password and security hash attributes.
    """
    id: int
    name: str
    email: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    """
    Login request payload.
    Requires valid email format and password string.
    """
    email: EmailStr = Field(..., description="User account email")
    password: str = Field(..., min_length=1, description="Account password")


class TokenResponse(BaseModel):
    """
    JWT authentication response.
    Returns access token, token type, and expiration in seconds.
    Never exposes password or password_hash.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    """Optional payload for token refresh (if not sent via cookie)."""
    refresh_token: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    """Payload for initiating a password reset."""
    email: EmailStr = Field(..., description="Account email address")


class ForgotPasswordResponse(BaseModel):
    """
    Safe public response for forgot password requests.
    Exposes only a generic confirmation message; never leaks tokens or reset URLs.
    """
    message: str = "If an account exists for this email, a password reset link has been sent."


class ResetPasswordRequest(BaseModel):
    """Payload for resetting a password using a one-time token."""
    token: str = Field(..., min_length=1, description="One-time password reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password (minimum 8 characters)")

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Token cannot be empty or whitespace only.")
        return cleaned

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class ResetPasswordResponse(BaseModel):
    """Safe public response for password reset completion."""
    message: str = "Password has been successfully reset."


class UpdateProfileRequest(BaseModel):
    """Payload for updating user profile name."""
    name: str = Field(..., min_length=1, max_length=255, description="Updated full name")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty or whitespace only.")
        return cleaned


class ChangePasswordRequest(BaseModel):
    """Payload for changing authenticated user password."""
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password (minimum 8 characters)")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class ChangePasswordResponse(BaseModel):
    """Safe public response for password change."""
    message: str = "Password has been successfully updated."


class DeleteAccountRequest(BaseModel):
    """Payload for permanently deleting an authenticated user account."""
    current_password: str = Field(..., min_length=1, description="Current password to authorize permanent account deletion")
    confirmation: str = Field(..., description="Explicit confirmation phrase, must be 'DELETE'")

    @field_validator("confirmation")
    @classmethod
    def validate_confirmation(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned != "DELETE":
            raise ValueError("Confirmation must be exactly 'DELETE'.")
        return cleaned


class DeleteAccountResponse(BaseModel):
    """Safe public response for account deletion."""
    message: str = "Your account has been permanently deleted."

