"""
Auth Router
===========
Traditional authentication endpoints: register, login, logout, token refresh.
All endpoints write audit logs and return educational context.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
from sqlmodel import Session
import re

from app.database.db import get_session
from app.services.auth_service import (
    register_user, authenticate_user, refresh_access_token,
    logout_user
)
from app.auth.hashing import analyze_password_strength
from app.auth.dependencies import get_current_user
from app.models.models import User, Role
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["auth"])


# ─────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str = ""

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", v):
            raise ValueError("Username must be 3-30 characters: letters, numbers, underscores only")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_strong_enough(cls, v):
        errors = []
        if len(v) < 8: errors.append("at least 8 characters")
        if not any(c.isupper() for c in v): errors.append("an uppercase letter")
        if not any(c.islower() for c in v): errors.append("a lowercase letter")
        if not any(c.isdigit() for c in v): errors.append("a digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in v):
            errors.append("a special character")
        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ─────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────

@router.post("/register")
async def register(
    data: RegisterRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Register a new user account.

    Security measures demonstrated:
    - Input validation (Pydantic)
    - Password complexity enforcement
    - Email uniqueness check
    - Argon2id password hashing
    - Audit logging
    """
    ip = request.client.host if request.client else ""
    user = register_user(
        session=session,
        username=data.username,
        email=data.email,
        password=data.password,
        full_name=data.full_name,
        ip_address=ip,
    )
    strength = analyze_password_strength(data.password)
    return {
        "success": True,
        "message": "Account created successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
        "educational": {
            "password_strength": strength,
            "note": "Your password was hashed with Argon2id before storage. The original password is never stored.",
        }
    }


@router.post("/login")
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    """
    Traditional username/password login.
    Issues JWT access token + refresh token.
    Sets both as HttpOnly cookies AND returns in response body (for API clients).

    Security demonstrated:
    - Account lockout after 5 failed attempts
    - Timing-safe password comparison
    - HttpOnly, SameSite cookie flags
    - Audit logging of all attempts
    """
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    user, access_token, refresh_token, access_expiry = authenticate_user(
        session=session,
        username=data.username,
        password=data.password,
        ip_address=ip,
        user_agent=ua,
    )

    role = session.get(Role, user.role_id)
    role_name = role.name if role else "user"

    # Set HttpOnly cookies (can't be read by JavaScript — XSS protection)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,          # Cannot be accessed by JavaScript
        samesite="lax",         # CSRF protection
        secure=False,           # True in production (HTTPS only)
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/auth/refresh",  # Scope refresh token to refresh endpoint only
    )

    return {
        "success": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": role_name,
        },
        "educational": {
            "cookie_flags": {
                "httponly": True,
                "samesite": "lax",
                "secure": "production only",
            },
            "token_expiry": f"Access token expires in {settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES} minutes",
            "why_short": "Short access token lifetime limits damage if a token is stolen",
        }
    }


@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    """
    Exchange a refresh token for a new access token pair.

    Implements Refresh Token Rotation:
    - Old refresh token is immediately revoked
    - New refresh token is issued
    - If a revoked token is reused, it indicates theft → all tokens revoked

    Token is read from HttpOnly cookie or request body.
    """
    ip = request.client.host if request.client else ""

    # Try cookie first, then body
    raw_token = request.cookies.get("refresh_token")
    if not raw_token:
        try:
            body = await request.json()
            raw_token = body.get("refresh_token")
        except Exception:
            pass

    if not raw_token:
        raise HTTPException(status_code=401, detail="No refresh token provided")

    new_access, new_refresh, expiry = refresh_access_token(
        session=session,
        raw_refresh_token=raw_token,
        ip_address=ip,
    )

    response.set_cookie("access_token", new_access, httponly=True, samesite="lax")
    response.set_cookie(
        "refresh_token", new_refresh, httponly=True, samesite="lax",
        path="/api/auth/refresh"
    )

    return {
        "success": True,
        "access_token": new_access,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "educational": {
            "rotation": "The old refresh token is now invalid. Using it again would trigger theft detection.",
        }
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Logout: revoke refresh token and clear cookies."""
    raw_refresh = request.cookies.get("refresh_token")
    logout_user(session=session, user_id=current_user.id, refresh_token_raw=raw_refresh)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return {"success": True, "message": "Logged out successfully"}


@router.get("/me")
async def me(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Get current authenticated user's profile."""
    role = session.get(Role, current_user.role_id)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": role.name if role else "user",
        "role_level": role.level if role else 0,
        "department": current_user.department,
        "clearance_level": current_user.clearance_level,
        "membership_status": current_user.membership_status,
        "mfa_enabled": current_user.mfa_enabled,
        "is_verified": current_user.is_verified,
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
    }
