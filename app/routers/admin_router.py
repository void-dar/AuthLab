"""
Admin Router
============
Protected admin dashboard endpoints.
All require 'admin' role — demonstrated via require_role() dependency.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select, desc
from pydantic import BaseModel

from app.database.db import get_session
from app.auth.dependencies import require_role, get_user_permissions
from app.models.models import (
    User, Role, Permission, RolePermission,
    AuditLog, LoginAttempt, RefreshToken, Session as DBSession,
    Post
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


def utcnow():
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────
# DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────

@router.get("/dashboard")
async def dashboard(
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin", "moderator")),
):
    """Admin dashboard — aggregate statistics."""
    # User stats
    all_users = session.exec(select(User)).all()
    active_users = [u for u in all_users if u.is_active]
    locked_users = [u for u in all_users if u.is_locked]

    # Login attempt stats (last 24h)
    from datetime import timedelta
    since = utcnow() - timedelta(hours=24)
    recent_attempts = session.exec(
        select(LoginAttempt).where(LoginAttempt.created_at >= since)
    ).all()
    failed_attempts = [a for a in recent_attempts if not a.success]

    # Token stats
    active_refresh_tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > utcnow(),
        )
    ).all()

    # Active sessions
    active_sessions = session.exec(
        select(DBSession).where(
            DBSession.is_active == True,
            DBSession.expires_at > utcnow(),
        )
    ).all()

    # Recent audit logs
    recent_logs = session.exec(
        select(AuditLog).order_by(desc(AuditLog.created_at)).limit(10)
    ).all()

    # Security events (critical severity)
    critical_events = session.exec(
        select(AuditLog).where(
            AuditLog.severity == "critical",
            AuditLog.created_at >= since,
        )
    ).all()

    return {
        "stats": {
            "total_users": len(all_users),
            "active_users": len(active_users),
            "locked_accounts": len(locked_users),
            "login_attempts_24h": len(recent_attempts),
            "failed_logins_24h": len(failed_attempts),
            "active_tokens": len(active_refresh_tokens),
            "active_sessions": len(active_sessions),
            "audit_events_24h": len(recent_logs),
        },
        "recent_events": [
            {
                "id": log.id,
                "event_type": log.action,
                "username": log.username,
                "result": log.result,
                "severity": log.severity,
                "ip_address": log.ip_address,
                "details": log.details,
                "created_at": log.created_at.isoformat(),
            }
            for log in recent_logs
        ],
        "recent_login_attempts": [
            {
                "username": a.username_tried,
                "ip_address": a.ip_address,
                "success": a.success,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_attempts[:10]
        ],
    }


# ─────────────────────────────────────────────────────────────
# USER MANAGEMENT
# ─────────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin", "moderator")),
):
    """List all users with their roles and security status."""
    users = session.exec(select(User).order_by(User.created_at)).all()
    result = []
    for u in users:
        role = session.get(Role, u.role_id)
        result.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": role.name if role else "unknown",
            "role_level": role.level if role else 0,
            "is_active": u.is_active,
            "is_locked": u.is_locked,
            "is_verified": u.is_verified,
            "mfa_enabled": u.mfa_enabled,
            "failed_login_count": u.failed_login_count,
            "locked_until": u.locked_until.isoformat() if u.locked_until else None,
            "department": u.department,
            "clearance_level": u.clearance_level,
            "country": u.country,
            "membership_status": u.membership_status,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat(),
        })
    return {"users": result, "total": len(result)}


@router.post("/users/{user_id}/unlock")
async def unlock_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """Unlock a locked user account."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.is_locked = False
    user.failed_login_count = 0
    user.locked_until = None
    session.add(user)
    session.commit()
    return {"success": True, "message": f"User {user.username} unlocked"}


@router.post("/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    request_body: dict,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """Change a user's role (admin only)."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    role_name = request_body.get("role")
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(400, f"Unknown role: {role_name}")

    old_role = session.get(Role, user.role_id)
    user.role_id = role.id
    session.add(user)
    session.commit()

    return {
        "success": True,
        "user": user.username,
        "old_role": old_role.name if old_role else "unknown",
        "new_role": role.name,
    }


# ─────────────────────────────────────────────────────────────
# AUDIT LOGS
# ─────────────────────────────────────────────────────────────

@router.get("/logs")
async def get_audit_logs(
    limit: int = 100,
    severity: str = None,
    event_type: str = None,
    action: str = None,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """Retrieve audit logs with optional filtering."""
    query = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
    logs = session.exec(query).all()

    filter_val = event_type or action
    if severity:
        logs = [l for l in logs if l.severity == severity]
    if filter_val:
        logs = [l for l in logs if filter_val.upper() in l.action.upper()]

    return {
        "logs": [
            {
                "id": log.id,
                "event_type": log.action,
                "username": log.username,
                "user_id": log.user_id,
                "result": log.result,
                "severity": log.severity,
                "resource": log.resource,
                "ip_address": log.ip_address,
                "details": log.details,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "total": len(logs),
    }


# ─────────────────────────────────────────────────────────────
# TOKEN MANAGEMENT
# ─────────────────────────────────────────────────────────────

@router.get("/tokens")
async def list_tokens(
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """List all refresh tokens with their status."""
    tokens = session.exec(
        select(RefreshToken).order_by(desc(RefreshToken.created_at)).limit(100)
    ).all()

    result = []
    for t in tokens:
        user = session.get(User, t.user_id)
        result.append({
            "id": t.id,
            "username": user.username if user else "unknown",
            "is_revoked": t.is_revoked,
            "is_expired": datetime.now() > t.expires_at.replace(tzinfo=None) if t.expires_at else False,
            "created_at": t.created_at.isoformat(),
            "expires_at": t.expires_at.isoformat(),
            "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
            "ip_address": t.ip_address,
            "family": t.family,
        })

    return {"tokens": result, "total": len(result)}


@router.delete("/tokens/{token_id}")
async def revoke_token(
    token_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """Manually revoke a refresh token (e.g., on account compromise)."""
    token = session.get(RefreshToken, token_id)
    if not token:
        raise HTTPException(404, "Token not found")
    token.is_revoked = True
    token.revoked_at = utcnow()
    session.add(token)
    session.commit()
    return {"success": True, "message": "Token revoked"}


# ─────────────────────────────────────────────────────────────
# PERMISSION MATRIX
# ─────────────────────────────────────────────────────────────

@router.get("/permissions/matrix")
async def permission_matrix(
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin", "moderator")),
):
    """
    Return the full RBAC permission matrix.
    Shows which roles have which permissions.
    """
    roles = session.exec(select(Role).order_by(desc(Role.level))).all()
    permissions = session.exec(select(Permission).order_by(Permission.resource)).all()

    matrix = {}
    for role in roles:
        role_perms = session.exec(
            select(RolePermission).where(RolePermission.role_id == role.id)
        ).all()
        perm_ids = {rp.permission_id for rp in role_perms}
        matrix[role.name] = {
            "level": role.level,
            "description": role.description,
            "permissions": {
                p.name: p.id in perm_ids for p in permissions
            }
        }

    return {
        "roles": [{"name": r.name, "level": r.level, "description": r.description} for r in roles],
        "permissions": [{"name": p.name, "resource": p.resource, "action": p.action} for p in permissions],
        "matrix": matrix,
    }


# ─────────────────────────────────────────────────────────────
# LOGIN ATTEMPTS (Brute Force Monitor)
# ─────────────────────────────────────────────────────────────

@router.get("/login-attempts")
async def login_attempts(
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_role("admin")),
):
    """View all login attempts for brute-force monitoring."""
    attempts = session.exec(
        select(LoginAttempt).order_by(desc(LoginAttempt.created_at)).limit(limit)
    ).all()

    return {
        "attempts": [
            {
                "id": a.id,
                "username_tried": a.username_tried,
                "ip_address": a.ip_address,
                "success": a.success,
                "failure_reason": a.failure_reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in attempts
        ],
        "total": len(attempts),
        "failed": len([a for a in attempts if not a.success]),
    }
