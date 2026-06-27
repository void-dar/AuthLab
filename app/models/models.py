"""
AuthLab Database Models
=======================
SQLModel models that serve dual purpose: SQLAlchemy ORM table definitions
AND Pydantic schema validation. This is one of SQLModel's key advantages
over using raw SQLAlchemy + separate Pydantic schemas for every entity.

Design decisions:
- Soft deletes on Users (is_active flag) — never hard-delete user records
- Separate tables for sessions, tokens, OTPs rather than storing in User row
- Audit log is append-only — never update, only insert
- All timestamps in UTC
"""
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field, Column, String
import sqlalchemy as sa


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────
# ROLES & PERMISSIONS
# ─────────────────────────────────────────────────────────────

class Role(SQLModel, table=True):
    """
    RBAC Role definition.
    Hierarchy: admin > moderator > staff > user > guest
    """
    __tablename__ = "roles"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(50), unique=True, nullable=False))
    description: str = Field(default="")
    level: int = Field(default=0)       # Higher = more privileged
    created_at: datetime = Field(default_factory=utcnow)


class Permission(SQLModel, table=True):
    """
    Fine-grained permission strings, e.g. "posts:delete", "users:ban"
    Permissions are assigned to roles, not directly to users (RBAC).
    """
    __tablename__ = "permissions"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    resource: str = Field(default="")      # e.g. "posts", "users"
    action: str = Field(default="")        # e.g. "read", "write", "delete"
    description: str = Field(default="")


class RolePermission(SQLModel, table=True):
    """Join table: which permissions belong to which role."""
    __tablename__ = "role_permissions"

    role_id: int = Field(foreign_key="roles.id", primary_key=True)
    permission_id: int = Field(foreign_key="permissions.id", primary_key=True)


# ─────────────────────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────────────────────

class User(SQLModel, table=True):
    """
    Core user entity.

    Security notes:
    - password_hash: NEVER store plaintext. Always Argon2id.
    - is_active: soft-delete mechanism
    - is_locked: brute-force lockout flag
    - mfa_enabled: whether TOTP is configured
    - failed_login_count + locked_until: account lockout system

    ABAC attributes (department, clearance_level, country, membership_status)
    are stored here for the ABAC authorization demo.
    """
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(sa_column=Column(String(50), unique=True, nullable=False, index=True))
    email: str = Field(sa_column=Column(String(255), unique=True, nullable=False, index=True))
    password_hash: str = Field(nullable=False)
    full_name: str = Field(default="")

    # Role (RBAC)
    role_id: int = Field(foreign_key="roles.id", default=5)  # default: guest

    # Account state
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_locked: bool = Field(default=False)
    failed_login_count: int = Field(default=0)
    locked_until: Optional[datetime] = Field(default=None)

    # MFA
    mfa_enabled: bool = Field(default=False)
    mfa_secret: Optional[str] = Field(default=None)   # TOTP secret (stored encrypted in prod)

    # ABAC attributes — used for attribute-based access control demo
    department: str = Field(default="general")         # e.g. engineering, finance, hr
    clearance_level: int = Field(default=1)            # 1-5
    age: int = Field(default=18)
    country: str = Field(default="NG")
    membership_status: str = Field(default="free")     # free, premium, enterprise

    # Timestamps
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_login_at: Optional[datetime] = Field(default=None)
    password_changed_at: Optional[datetime] = Field(default_factory=utcnow)


# ─────────────────────────────────────────────────────────────
# SESSIONS (for session-based auth demo)
# ─────────────────────────────────────────────────────────────

class Session(SQLModel, table=True):
    """
    Server-side session storage for the session-based auth demo.
    Shows contrast with stateless JWT approach.

    Security: session_id must be cryptographically random (secrets.token_hex)
    """
    __tablename__ = "sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(sa_column=Column(String(128), unique=True, nullable=False, index=True))
    user_id: int = Field(foreign_key="users.id", nullable=False)

    # Session data (JSON stringified for simplicity)
    data: str = Field(default="{}")

    ip_address: str = Field(default="")
    user_agent: str = Field(default="")

    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)
    last_accessed_at: datetime = Field(default_factory=utcnow)


# ─────────────────────────────────────────────────────────────
# JWT REFRESH TOKENS
# ─────────────────────────────────────────────────────────────

class RefreshToken(SQLModel, table=True):
    """
    Stored refresh tokens for the JWT rotation demo.

    Why store refresh tokens server-side when JWTs are "stateless"?
    Because refresh tokens MUST be revocable. If a user logs out
    or an account is compromised, we need to invalidate the refresh token.
    Access tokens are short-lived enough to not need storage.
    """
    __tablename__ = "refresh_tokens"

    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(sa_column=Column(String(255), unique=True, nullable=False))
    user_id: int = Field(foreign_key="users.id", nullable=False)
    family: str = Field(default="")       # Token rotation family — detect reuse
    is_revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)
    revoked_at: Optional[datetime] = Field(default=None)
    ip_address: str = Field(default="")


# ─────────────────────────────────────────────────────────────
# OTP / MFA CODES
# ─────────────────────────────────────────────────────────────

class OTPCode(SQLModel, table=True):
    """
    Temporary OTP codes for the MFA demo.
    Each record is single-use and expires quickly.
    """
    __tablename__ = "otp_codes"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)
    code: str = Field(nullable=False)        # Hashed in real system, plain here for demo visibility
    purpose: str = Field(default="login")    # login, verify_email, etc.
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)
    used_at: Optional[datetime] = Field(default=None)


# ─────────────────────────────────────────────────────────────
# PASSWORD RESET TOKENS
# ─────────────────────────────────────────────────────────────

class PasswordResetToken(SQLModel, table=True):
    """
    Short-lived, single-use tokens for password reset flow.
    Token is hashed before storage — raw token only sent to user.
    """
    __tablename__ = "password_reset_tokens"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)
    token_hash: str = Field(sa_column=Column(String(255), unique=True, nullable=False))
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)
    used_at: Optional[datetime] = Field(default=None)


# ─────────────────────────────────────────────────────────────
# MAGIC LINK TOKENS (Passwordless)
# ─────────────────────────────────────────────────────────────

class MagicLinkToken(SQLModel, table=True):
    """
    Magic link tokens for the passwordless auth demo.
    Same security model as password reset — short-lived, single-use, hashed.
    """
    __tablename__ = "magic_link_tokens"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)
    token_hash: str = Field(sa_column=Column(String(255), unique=True, nullable=False))
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)


# ─────────────────────────────────────────────────────────────
# OAUTH SIMULATION
# ─────────────────────────────────────────────────────────────

class OAuthClient(SQLModel, table=True):
    """Simulated OAuth 2.0 client applications."""
    __tablename__ = "oauth_clients"

    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: str = Field(sa_column=Column(String(128), unique=True, nullable=False))
    client_secret_hash: str = Field(nullable=False)
    name: str = Field(nullable=False)
    description: str = Field(default="")
    redirect_uri: str = Field(nullable=False)
    allowed_scopes: str = Field(default="openid profile email")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)


class OAuthAuthCode(SQLModel, table=True):
    """Authorization codes issued during OAuth flow (step 2 of auth code flow)."""
    __tablename__ = "oauth_auth_codes"

    id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(sa_column=Column(String(255), unique=True, nullable=False))
    client_id: str = Field(nullable=False)
    user_id: int = Field(foreign_key="users.id", nullable=False)
    scope: str = Field(default="openid profile email")
    redirect_uri: str = Field(nullable=False)
    code_challenge: Optional[str] = Field(default=None)  # PKCE
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)


# ─────────────────────────────────────────────────────────────
# POSTS (for Resource Ownership demo)
# ─────────────────────────────────────────────────────────────

class Post(SQLModel, table=True):
    """
    Simple post entity to demonstrate resource ownership authorization.
    Rule: users can only edit/delete their OWN posts.
    Admins can edit/delete ANY post.
    This is the core of IBAC (Identity-Based Access Control).
    """
    __tablename__ = "posts"

    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(nullable=False)
    content: str = Field(default="")
    owner_id: int = Field(foreign_key="users.id", nullable=False)
    is_public: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ─────────────────────────────────────────────────────────────
# AUDIT LOGS
# ─────────────────────────────────────────────────────────────

class AuditLog(SQLModel, table=True):
    """
    Append-only audit trail.
    Every security-relevant action is logged here.
    In production: ship to SIEM (Splunk, ELK, Datadog).

    Rule: NEVER update or delete audit logs — only INSERT.
    """
    __tablename__ = "audit_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None)   # NULL for anonymous actions
    username: str = Field(default="anonymous")
    action: str = Field(nullable=False)             # e.g. "LOGIN_SUCCESS", "TOKEN_REFRESH"
    resource: str = Field(default="")               # e.g. "/api/posts/42"
    result: str = Field(default="success")          # success | failure | blocked
    ip_address: str = Field(default="")
    user_agent: str = Field(default="")
    details: str = Field(default="{}")              # JSON string for extra context
    severity: str = Field(default="info")           # info | warning | critical
    created_at: datetime = Field(default_factory=utcnow)


# ─────────────────────────────────────────────────────────────
# LOGIN ATTEMPTS (for brute-force demo)
# ─────────────────────────────────────────────────────────────

class LoginAttempt(SQLModel, table=True):
    """
    Tracks all login attempts for brute-force detection and demo visualization.
    Used by the account lockout system and the attack demonstration.
    """
    __tablename__ = "login_attempts"

    id: Optional[int] = Field(default=None, primary_key=True)
    username_tried: str = Field(nullable=False)
    ip_address: str = Field(default="")
    success: bool = Field(default=False)
    failure_reason: str = Field(default="")   # wrong_password, user_not_found, locked, etc.
    created_at: datetime = Field(default_factory=utcnow)


# ─────────────────────────────────────────────────────────────
# SSO SIMULATION
# ─────────────────────────────────────────────────────────────

class SSOSession(SQLModel, table=True):
    """
    Central SSO session that links user across simulated apps.
    When user logs into App A, this record is created.
    App B checks this record to grant access without re-login.
    """
    __tablename__ = "sso_sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    sso_token: str = Field(sa_column=Column(String(255), unique=True, nullable=False))
    user_id: int = Field(foreign_key="users.id", nullable=False)
    apps_accessed: str = Field(default="[]")     # JSON list of apps accessed this session
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(nullable=False)
