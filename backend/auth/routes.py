"""
Authentication API routes for SecureCode AI.
Handles user registration with Argon2 hashing and database persistence.
"""

from typing import Optional
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User, PasswordResetToken
from .schemas import (
    RegisterRequest,
    UserResponse,
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    UpdateProfileRequest,
    ChangePasswordRequest,
    ChangePasswordResponse,
    DeleteAccountRequest,
    DeleteAccountResponse,
)
from .security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    generate_reset_token,
    hash_reset_token,
    get_reset_url,
    get_refresh_cookie_settings,
    RESET_TOKEN_EXPIRE_MINUTES,
)
from .dependencies import get_current_user
from .email import send_password_reset_email


router = APIRouter()




@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register_user(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    """
    Registers a new user account with secure Argon2 password hashing.
    Rejects duplicate emails with HTTP 409 Conflict.
    Returns safe user details without any password or hash exposure.
    """
    # 1. Normalize email
    normalized_email = payload.email.strip().lower()

    # 2. Check for duplicate email
    try:
        existing_user = db.query(User).filter(User.email == normalized_email).first()
    except Exception as err:
        print(f"[AUTH ERROR] Failed to query existing user: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during registration check.",
        )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # 3. Hash password with Argon2
    try:
        hashed_password = hash_password(payload.password)
    except Exception as err:
        print(f"[AUTH ERROR] Failed to hash password: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to securely process password.",
        )

    # 4. Create and persist user entity
    new_user = User(
        name=payload.name.strip(),
        email=normalized_email,
        password_hash=hashed_password,
        is_active=True,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print("[AUTH] Registration successful")
    except Exception as err:
        db.rollback()
        print(f"[AUTH ERROR] Failed to save user: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating your account.",
        )

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT access token",
)
def login_user(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticates an existing user account using Argon2 password verification.
    Issues a signed JWT access token and sets an HttpOnly refresh token cookie.
    Returns HTTP 401 with a generic error message for invalid credentials.
    """
    # 1. Normalize email
    normalized_email = payload.email.strip().lower()

    # 2. Query user by normalized email
    try:
        user = db.query(User).filter(User.email == normalized_email).first()
    except Exception as err:
        print(f"[AUTH ERROR] Database error during login lookup: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database service error during authentication.",
        )

    # 3. Uniform credential verification (constant-time Argon2 verification)
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        print("[AUTH] Login rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Generate signed JWT access token and refresh token
    try:
        access_token, expires_in = create_access_token(
            user_id=user.id,
            email=user.email,
        )
        refresh_token, refresh_expires_in = create_refresh_token(
            user_id=user.id,
        )
        # Set HttpOnly refresh token cookie
        cookie_settings = get_refresh_cookie_settings()
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=refresh_expires_in,
            httponly=cookie_settings.get("httponly", True),
            samesite=cookie_settings.get("samesite", "lax"),
            secure=cookie_settings.get("secure", False),
            path=cookie_settings.get("path", "/"),
        )
        print("[AUTH] Login successful")
    except Exception as err:
        print(f"[AUTH ERROR] Failed to generate JWT token: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate authentication token.",
        )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Returns profile information for the currently authenticated user.
    Requires a valid JWT access token.
    """
    return current_user


@router.patch(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update current authenticated user's profile information",
)
def update_me(
    payload: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Updates the authenticated user's display name.
    Requires a valid JWT access token.
    """
    current_user.name = payload.name.strip()
    try:
        db.commit()
        db.refresh(current_user)
        print("[AUTH] User profile updated successfully")
    except Exception as err:
        db.rollback()
        print(f"[AUTH ERROR] Failed to update user profile: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile information.",
        )
    return current_user


@router.delete(
    "/me",
    response_model=DeleteAccountResponse,
    status_code=status.HTTP_200_OK,
    summary="Permanently delete current authenticated user account",
)
def delete_me(
    payload: DeleteAccountRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Permanently deletes the current authenticated user's account from MySQL.
    Requires:
    1. Valid JWT authentication (resolves current_user).
    2. Verification of current password using Argon2.
    3. Explicit confirmation string 'DELETE'.
    Cleans up associated PasswordResetToken records.
    Clears the HttpOnly refresh token cookie.
    Does NOT modify or reset guest trial entitlements or cookies.
    """
    # 1. Verify current password
    if not verify_password(payload.current_password, current_user.password_hash):
        print("[AUTH] Account deletion rejected: incorrect password")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # 2. Verify confirmation phrase
    if payload.confirmation != "DELETE":
        print("[AUTH] Account deletion rejected: invalid confirmation string")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please type DELETE to confirm account deletion.",
        )

    user_id = current_user.id
    user_email = current_user.email

    try:
        # Cascade/clean up any password reset tokens associated with this user
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user_id).delete(synchronize_session=False)

        # Permanently delete user from database
        db.delete(current_user)
        db.commit()
        print(f"[AUTH] Account permanently deleted for user_id={user_id}")
    except Exception as err:
        db.rollback()
        print(f"[AUTH ERROR] Failed to delete user {user_id}: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while deleting your account. Please try again.",
        )

    # Clear refresh token cookie
    cookie_settings = get_refresh_cookie_settings()
    response.delete_cookie(
        key="refresh_token",
        path=cookie_settings.get("path", "/"),
        httponly=cookie_settings.get("httponly", True),
        samesite=cookie_settings.get("samesite", "lax"),
    )

    return DeleteAccountResponse(message="Your account has been permanently deleted.")


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token using refresh token cookie",
)
def refresh_token(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Refreshes an expired access token using the HttpOnly refresh_token cookie
    or optional request body payload.
    Rejects access tokens used as refresh tokens.
    """
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh and payload and payload.refresh_token:
        raw_refresh = payload.refresh_token.strip()

    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        decoded = decode_refresh_token(raw_refresh)
        user_id = int(decoded.get("sub"))
    except (jwt.PyJWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired refresh token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_access_token, expires_in = create_access_token(
        user_id=user.id,
        email=user.email,
    )
    new_refresh_token, refresh_expires_in = create_refresh_token(
        user_id=user.id,
    )
    cookie_settings = get_refresh_cookie_settings()
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        max_age=refresh_expires_in,
        httponly=cookie_settings.get("httponly", True),
        samesite=cookie_settings.get("samesite", "lax"),
        secure=cookie_settings.get("secure", False),
        path=cookie_settings.get("path", "/"),
    )

    return TokenResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Log out user and clear refresh token cookie",
)
def logout_user(response: Response):
    """
    Clears the HttpOnly refresh token cookie.
    """
    cookie_settings = get_refresh_cookie_settings()
    response.delete_cookie(
        key="refresh_token",
        path=cookie_settings.get("path", "/"),
        httponly=cookie_settings.get("httponly", True),
        samesite=cookie_settings.get("samesite", "lax"),
    )
    return {"message": "Successfully logged out"}


@router.post(
    "/change-password",
    response_model=ChangePasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Change password for authenticated user",
)
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Verifies current password and updates to a new Argon2-hashed password.
    Requires authenticated user. Never logs passwords.
    """
    if not verify_password(payload.current_password, current_user.password_hash):
        print("[AUTH] Change password rejected: incorrect current password")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    try:
        current_user.password_hash = hash_password(payload.new_password)
        db.commit()
        print("[AUTH] User password changed successfully")
    except Exception as err:
        db.rollback()
        print(f"[AUTH ERROR] Failed to change password: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password. Please try again.",
        )

    return ChangePasswordResponse(message="Password has been successfully updated.")


# =========================================================
# FORGOT & RESET PASSWORD ENDPOINTS
# =========================================================

@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a secure password reset link",
)
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Initiates a password reset flow.
    Normalizes email, checks user existence without revealing account presence,
    generates a secure 20-minute one-time reset token, and delivers reset link ONLY via Brevo SMTP email.
    Always returns a safe generic message to prevent email enumeration.
    Never exposes reset token or reset URL in the API response.
    """
    normalized_email = payload.email.strip().lower()
    print("[AUTH] Password reset requested")

    # Find user in MySQL
    try:
        user = db.query(User).filter(User.email == normalized_email).first()
    except Exception as err:
        print(f"[AUTH ERROR] Database lookup failed during forgot-password: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database service error during password reset request.",
        )

    if user and user.is_active:
        # Generate secure random token
        raw_token = generate_reset_token()
        hashed_token = hash_reset_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)

        try:
            # Invalidate any previously unused reset tokens for this user
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False,
            ).update({"used": True}, synchronize_session=False)

            # Store the new token hash
            reset_record = PasswordResetToken(
                user_id=user.id,
                token_hash=hashed_token,
                expires_at=expires_at,
                used=False,
            )
            db.add(reset_record)
            db.commit()

            # Construct reset URL for email delivery only
            reset_url = get_reset_url(raw_token)
        except Exception as err:
            db.rollback()
            print(f"[AUTH ERROR] Failed to record password reset token: {err}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate password reset request.",
            )

        # Dispatch branded password reset email via Brevo SMTP
        try:
            email_sent, email_err = send_password_reset_email(
                to_email=user.email,
                reset_url=reset_url,
                expire_minutes=RESET_TOKEN_EXPIRE_MINUTES,
            )
            if email_sent:
                print("[AUTH] Reset email accepted by provider")
            else:
                print(f"[AUTH EMAIL WARNING] Password reset email not sent: {email_err}")
        except Exception as dispatch_err:
            print(f"[AUTH EMAIL ERROR] Unexpected error during email dispatch: {type(dispatch_err).__name__}")

    # Always return safe generic message to prevent email enumeration (never leak token or URL)
    return ForgotPasswordResponse(
        message="If an account exists for this email, a password reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset password using one-time token",
)
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Resets user password using a valid, non-expired, one-time reset token.
    Hashes the new password using Argon2, updates MySQL users table,
    and invalidates the reset token immediately.
    """
    raw_token = payload.token.strip()
    hashed_token = hash_reset_token(raw_token)

    try:
        reset_record = db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == hashed_token
        ).first()
    except Exception as err:
        print(f"[AUTH ERROR] Database error querying reset token: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database service error during token validation.",
        )

    # Validate token exists and is not already used
    if not reset_record or reset_record.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # Normalize expires_at for timezone comparison
    now = datetime.now(timezone.utc)
    expires_at = reset_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now > expires_at:
        # Mark expired token as used
        reset_record.used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # Find associated user
    user = db.query(User).filter(User.id == reset_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # Hash new password using Argon2
    try:
        new_hash = hash_password(payload.new_password)
    except Exception as err:
        print(f"[AUTH ERROR] Failed to hash new password: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to securely process password.",
        )

    try:
        # Update user password and invalidate token
        user.password_hash = new_hash
        reset_record.used = True
        db.commit()
        print("[AUTH] Password reset successful")
    except Exception as err:
        db.rollback()
        print(f"[AUTH ERROR] Failed to update user password in DB: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password. Please try again.",
        )

    return ResetPasswordResponse(message="Password has been successfully reset.")

