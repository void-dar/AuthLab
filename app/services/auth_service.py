"""
Authentication Service
======================
Handles all authentication business logic.
Routes call services, services call repositories.
This separation keeps business logic testable and routes thin.
"""
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlmodel import Session, select
from fastapi import HTTPException, status

from app.models.models import (
    User, Role, Session as DBSession, RefreshToken,
    OTPCode, PasswordResetToken, MagicLinkToken,
    AuditLog, LoginAttempt
)
from app.auth.hashing import hash_password, verify_password
from app.auth.tokens import create_access_token, create_refresh_token
from app.config import get_settings

settings = get_settings()


def utcnow():
    return datetime.now(timezone.utc)

def utcnow_naive():
    return datetime.now()


# ─────────────────────────────────────────────────────────────
# AUDIT LOGGING HELPER
# ─────────────────────────────────────────────────────────────

def log_event(
    session: Session,
    action: str,
    result: str = "success",
    user_id: int = None,
    username: str = "anonymous",
    ip_address: str = "",
    user_agent: str = "",
    resource: str = "",
    details: dict = None,
    severity: str = "info",
):
    """Write an audit log entry. Call this for every security-relevant event."""
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        result=result,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details or {}),
        severity=severity,
    )
    session.add(entry)
    # Don't commit here — let the caller control the transaction


# ─────────────────────────────────────────────────────────────
# REGISTRATION
# ─────────────────────────────────────────────────────────────

def register_user(
    session: Session,
    username: str,
    email: str,
    password: str,
    full_name: str = "",
    ip_address: str = "",
) -> User:
    """
    Register a new user.
    Validates uniqueness, hashes password, assigns default 'user' role.
    """
    # Check uniqueness
    existing_username = session.exec(
        select(User).where(User.username == username)
    ).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")

    existing_email = session.exec(
        select(User).where(User.email == email)
    ).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Get default 'user' role
    user_role = session.exec(select(Role).where(Role.name == "user")).first()
    role_id = user_role.id if user_role else 4

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
        role_id=role_id,
        is_active=True,
        is_verified=False,   # Would send verification email in production
    )
    session.add(user)
    session.flush()  # Get user.id

    log_event(session, "USER_REGISTERED", user_id=user.id,
              username=username, ip_address=ip_address,
              details={"email": email})
    session.commit()
    session.refresh(user)
    return user


# ─────────────────────────────────────────────────────────────
# TRADITIONAL LOGIN
# ─────────────────────────────────────────────────────────────

def authenticate_user(
    session: Session,
    username: str,
    password: str,
    ip_address: str = "",
    user_agent: str = "",
) -> Tuple[User, str, str, datetime]:
    """
    Authenticate user with username/password.
    Returns (user, access_token, refresh_token_raw, access_token_expiry).
    Raises HTTPException on failure.
    """
    # Track this attempt
    attempt = LoginAttempt(
        username_tried=username,
        ip_address=ip_address,
        success=False,
    )

    # Find user (timing-safe: look up user regardless of existence)
    user = session.exec(select(User).where(User.username == username)).first()

    if not user:
        attempt.failure_reason = "user_not_found"
        session.add(attempt)
        log_event(session, "LOGIN_FAILED", result="failure",
                  username=username, ip_address=ip_address,
                  details={"reason": "user_not_found"}, severity="warning")
        session.commit()
        # Timing attack prevention: hash anyway so response time is consistent
        hash_password("dummy_password_to_prevent_timing_attack")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Check lockout
    if user.is_locked:
        if user.locked_until and utcnow() < user.locked_until:
            remaining = int((user.locked_until - utcnow()).total_seconds() / 60)
            attempt.failure_reason = "account_locked"
            session.add(attempt)
            log_event(session, "LOGIN_BLOCKED_LOCKED", result="blocked",
                      user_id=user.id, username=username, ip_address=ip_address,
                      severity="warning")
            session.commit()
            raise HTTPException(
                status_code=423,
                detail=f"Account locked due to too many failed attempts. Try again in {remaining} minutes."
            )
        else:
            # Lockout expired — unlock
            user.is_locked = False
            user.failed_login_count = 0
            user.locked_until = None

    if not user.is_active:
        attempt.failure_reason = "account_disabled"
        session.add(attempt)
        session.commit()
        raise HTTPException(status_code=401, detail="Account is disabled")

    # Verify password
    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        attempt.failure_reason = "wrong_password"

        # Lockout check
        if user.failed_login_count >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.is_locked = True
            user.locked_until = utcnow() + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            severity = "critical"
            log_event(session, "ACCOUNT_LOCKED", result="failure",
                      user_id=user.id, username=username, ip_address=ip_address,
                      details={"failed_attempts": user.failed_login_count},
                      severity="critical")
        else:
            severity = "warning"

        session.add(user)
        session.add(attempt)
        log_event(session, "LOGIN_FAILED", result="failure",
                  user_id=user.id, username=username, ip_address=ip_address,
                  details={"attempt": user.failed_login_count}, severity=severity)
        session.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Success — reset failure count
    user.failed_login_count = 0
    user.is_locked = False
    user.last_login_at = utcnow()
    attempt.success = True

    # Get role name
    role = session.get(Role, user.role_id)
    role_name = role.name if role else "user"

    # Issue tokens
    access_token, access_expiry = create_access_token(
        user_id=user.id, username=user.username, role=role_name
    )
    raw_refresh, refresh_hash, refresh_expiry = create_refresh_token(user_id=user.id)

    # Store refresh token
    db_refresh = RefreshToken(
        token_hash=refresh_hash,
        user_id=user.id,
        expires_at=refresh_expiry,
        ip_address=ip_address,
    )
    session.add(user)
    session.add(attempt)
    session.add(db_refresh)
    log_event(session, "LOGIN_SUCCESS", user_id=user.id,
              username=username, ip_address=ip_address, user_agent=user_agent)
    session.commit()

    return user, access_token, raw_refresh, access_expiry


# ─────────────────────────────────────────────────────────────
# TOKEN REFRESH
# ─────────────────────────────────────────────────────────────

def refresh_access_token(
    session: Session,
    raw_refresh_token: str,
    ip_address: str = "",
) -> Tuple[str, str, datetime]:
    """
    Exchange a valid refresh token for a new access + refresh token pair.
    Implements token rotation — old refresh token is revoked.
    Returns (new_access_token, new_refresh_token_raw, new_access_expiry).
    """
    token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()

    db_token = session.exec(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).first()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if db_token.is_revoked:
        # Token reuse detected! This could indicate theft.
        # In production: revoke ALL tokens for this user (entire family)
        log_event(session, "REFRESH_TOKEN_REUSE_DETECTED", result="failure",
                  user_id=db_token.user_id, severity="critical",
                  details={"token_family": db_token.family})
        session.commit()
        raise HTTPException(status_code=401, detail="Refresh token already used — possible token theft detected")

    if utcnow() > db_token.expires_at:
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = session.get(User, db_token.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    role = session.get(Role, user.role_id)
    role_name = role.name if role else "user"

    # Revoke old token (rotation)
    db_token.is_revoked = True
    db_token.revoked_at = utcnow()

    # Issue new tokens
    new_access, access_expiry = create_access_token(
        user_id=user.id, username=user.username, role=role_name
    )
    new_raw_refresh, new_hash, new_refresh_expiry = create_refresh_token(
        user_id=user.id, family=db_token.family
    )

    new_db_refresh = RefreshToken(
        token_hash=new_hash,
        user_id=user.id,
        family=db_token.family,
        expires_at=new_refresh_expiry,
        ip_address=ip_address,
    )

    session.add(db_token)
    session.add(new_db_refresh)
    log_event(session, "TOKEN_REFRESHED", user_id=user.id, username=user.username)
    session.commit()

    return new_access, new_raw_refresh, access_expiry


# ─────────────────────────────────────────────────────────────
# SESSION-BASED AUTH (demo)
# ─────────────────────────────────────────────────────────────

def create_session(
    session: Session,
    user: User,
    ip_address: str = "",
    user_agent: str = "",
) -> str:
    """Create a server-side session and return the session ID."""
    session_id = secrets.token_hex(32)
    expire = utcnow() + timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS)

    db_session = DBSession(
        session_id=session_id,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expire,
        data=json.dumps({"username": user.username, "role_id": user.role_id}),
    )
    session.add(db_session)
    log_event(session, "SESSION_CREATED", user_id=user.id,
              username=user.username, ip_address=ip_address)
    session.commit()
    return session_id


def get_session_user(session: Session, session_id: str) -> Optional[User]:
    """Look up a user by session ID."""
    db_session = session.exec(
        select(DBSession).where(
            DBSession.session_id == session_id,
            DBSession.is_active == True,
        )
    ).first()

    if not db_session:
        return None
    if utcnow() > db_session.expires_at:
        db_session.is_active = False
        session.add(db_session)
        session.commit()
        return None

    # Update last accessed
    db_session.last_accessed_at = utcnow()
    session.add(db_session)
    session.commit()

    return session.get(User, db_session.user_id)


def destroy_session(session: Session, session_id: str):
    """Invalidate a session (logout)."""
    db_session = session.exec(
        select(DBSession).where(DBSession.session_id == session_id)
    ).first()
    if db_session:
        db_session.is_active = False
        session.add(db_session)
        session.commit()


# ─────────────────────────────────────────────────────────────
# OTP / MFA
# ─────────────────────────────────────────────────────────────

def generate_otp(session: Session, user_id: int, purpose: str = "login") -> str:
    """Generate a 6-digit OTP, store it, and return it."""
    import random
    code = "".join([str(random.randint(0, 9)) for _ in range(settings.OTP_LENGTH)])
    expire = utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    otp = OTPCode(
        user_id=user_id,
        code=code,
        purpose=purpose,
        expires_at=expire,
    )
    session.add(otp)
    session.commit()
    return code


def verify_otp(session: Session, user_id: int, code: str, purpose: str = "login") -> bool:
    """Verify an OTP code. Single-use."""
    otp = session.exec(
        select(OTPCode).where(
            OTPCode.user_id == user_id,
            OTPCode.code == code,
            OTPCode.purpose == purpose,
            OTPCode.is_used == False,
        )
    ).first()
    print("utcnow:", utcnow(), utcnow().tzinfo)
    print("expires_at:", otp.expires_at, otp.expires_at.tzinfo)
    now = utcnow().replace(tzinfo=None)
    if not otp:
        return False
    if now > otp.expires_at:
        return False

    otp.is_used = True
    otp.used_at = utcnow()
    session.add(otp)
    session.commit()
    return True


# ─────────────────────────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────────────────────────

def generate_password_reset_token(session: Session, email: str) -> Optional[str]:
    """
    Generate a password reset token for a given email.
    Returns raw token (would be emailed in production).
    Returns None if email not found (but don't tell the user — prevents enumeration).
    """
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        return None  # Silently fail — don't reveal if email exists

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expire = utcnow() + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES)

    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expire,
    )
    session.add(reset)
    log_event(session, "PASSWORD_RESET_REQUESTED", user_id=user.id,
              username=user.username, details={"email": email})
    session.commit()
    return raw_token


def reset_password(session: Session, raw_token: str, new_password: str) -> bool:
    """Reset a user's password using a valid reset token."""
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    reset = session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.is_used == False,
        )
    ).first()

    if not reset:
        return False
    if utcnow() > reset.expires_at:
        return False

    user = session.get(User, reset.user_id)
    if not user:
        return False

    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()
    reset.is_used = True
    reset.used_at = utcnow()

    session.add(user)
    session.add(reset)
    log_event(session, "PASSWORD_RESET_COMPLETED", user_id=user.id,
              username=user.username, severity="warning")
    session.commit()
    return True


# ─────────────────────────────────────────────────────────────
# MAGIC LINK (Passwordless)
# ─────────────────────────────────────────────────────────────

def generate_magic_link(session: Session, email: str) -> Optional[Tuple[str, User]]:
    """Generate a magic link token. Returns (raw_token, user) or None."""
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        return None

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expire = utcnow() + timedelta(minutes=settings.MAGIC_LINK_EXPIRE_MINUTES)

    magic = MagicLinkToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expire,
    )
    session.add(magic)
    log_event(session, "MAGIC_LINK_GENERATED", user_id=user.id,
              username=user.username, details={"email": email})
    session.commit()
    return raw_token, user


def verify_magic_link(session: Session, raw_token: str) -> Optional[User]:
    """Verify a magic link token and return the authenticated user."""
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    magic = session.exec(
        select(MagicLinkToken).where(
            MagicLinkToken.token_hash == token_hash,
            MagicLinkToken.is_used == False,
        )
    ).first()

    if not magic:
        return None
    if utcnow() > magic.expires_at:
        return None

    user = session.get(User, magic.user_id)
    magic.is_used = True
    session.add(magic)
    log_event(session, "MAGIC_LINK_USED", user_id=user.id if user else None,
              username=user.username if user else "unknown")
    session.commit()
    return user


# ─────────────────────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────────────────────

def logout_user(session: Session, user_id: int, refresh_token_raw: str = None):
    """
    Logout: revoke refresh token and log the event.
    Access tokens can't be revoked (stateless), but they expire shortly.
    """
    if refresh_token_raw:
        token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
        db_token = session.exec(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        ).first()
        if db_token:
            db_token.is_revoked = True
            db_token.revoked_at = utcnow()
            session.add(db_token)

    log_event(session, "LOGOUT", user_id=user_id)
    session.commit()
