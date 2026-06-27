"""
Authorization Dependencies
===========================
FastAPI dependencies for role-based, attribute-based, and
resource-ownership authorization checks.

These are injected into route handlers via Depends().
This pattern separates authorization logic from business logic.

AUTHORIZATION vs AUTHENTICATION:
  Authentication:  Who are you? (identity)
  Authorization:   What can you do? (permissions)

These are two distinct concerns and should be implemented separately.
"""
from typing import Optional, Callable
from fastapi import Depends, HTTPException, Request, Cookie, status
from sqlmodel import Session, select

from app.database.db import get_session
from app.models.models import User, Role, Permission, RolePermission
from app.auth.tokens import verify_access_token


# ─────────────────────────────────────────────────────────────
# CURRENT USER EXTRACTION
# ─────────────────────────────────────────────────────────────

async def get_current_user_optional(
    request: Request,
    session: Session = Depends(get_session),
) -> Optional[User]:
    """
    Extract the current user from JWT token (if present).
    Returns None if not authenticated — for optional auth routes.
    """
    token = _extract_token(request)
    if not token:
        return None
    return _user_from_token(token, session)


async def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User:
    """
    Require authentication. Raises 401 if not authenticated.
    Use as: current_user: User = Depends(get_current_user)
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def _extract_token(request: Request) -> Optional[str]:
    """
    Try to extract JWT from:
    1. Authorization: Bearer <token> header
    2. access_token cookie
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]

    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    return None


def _user_from_token(token: str, session: Session) -> Optional[User]:
    """Validate token and fetch the corresponding user."""
    payload = verify_access_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    user = session.get(User, int(user_id))
    if not user or not user.is_active or user.is_locked:
        return None

    return user


# ─────────────────────────────────────────────────────────────
# RBAC — ROLE-BASED ACCESS CONTROL
# ─────────────────────────────────────────────────────────────

def require_role(*allowed_roles: str) -> Callable:
    """
    Factory: returns a dependency that restricts access to specified roles.

    Usage:
        @router.get("/admin")
        async def admin_page(user = Depends(require_role("admin"))):
            ...
    """
    async def _check_role(
        current_user: User = Depends(get_current_user),
        session: Session = Depends(get_session),
    ) -> User:
        role = session.get(Role, current_user.role_id)
        role_name = role.name if role else "guest"

        if role_name not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {list(allowed_roles)}. Your role: {role_name}"
            )
        return current_user

    return _check_role


def require_min_role_level(min_level: int) -> Callable:
    """
    Require a minimum role level (admin=100, mod=60, staff=40, user=20, guest=0).
    More flexible than listing specific roles.
    """
    async def _check_level(
        current_user: User = Depends(get_current_user),
        session: Session = Depends(get_session),
    ) -> User:
        role = session.get(Role, current_user.role_id)
        level = role.level if role else 0

        if level < min_level:
            role_name = role.name if role else "guest"
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privilege. Minimum level: {min_level}. Your level: {level} ({role_name})"
            )
        return current_user

    return _check_level


def require_permission(permission_name: str) -> Callable:
    """
    Permission-based access control.
    Checks if user's role has the specific permission.
    """
    async def _check_permission(
        current_user: User = Depends(get_current_user),
        session: Session = Depends(get_session),
    ) -> User:
        has_perm = _user_has_permission(current_user, permission_name, session)
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: '{permission_name}'"
            )
        return current_user

    return _check_permission


def _user_has_permission(user: User, permission_name: str, session: Session) -> bool:
    """Check if a user's role grants a specific permission."""
    perm = session.exec(
        select(Permission).where(Permission.name == permission_name)
    ).first()
    if not perm:
        return False

    rp = session.exec(
        select(RolePermission).where(
            RolePermission.role_id == user.role_id,
            RolePermission.permission_id == perm.id,
        )
    ).first()
    return rp is not None


# ─────────────────────────────────────────────────────────────
# ABAC — ATTRIBUTE-BASED ACCESS CONTROL
# ─────────────────────────────────────────────────────────────

class ABACPolicy:
    """
    Evaluates access based on user attributes.

    Unlike RBAC which uses static roles, ABAC evaluates dynamic
    conditions at request time.

    Example policy: "Only users in the finance department with
    clearance level >= 3 can access payroll data."
    """

    @staticmethod
    def can_access_financial_reports(user: User) -> tuple[bool, str]:
        """Finance reports: department=finance OR clearance >= 4."""
        if user.department == "finance":
            return True, "Department: finance"
        if user.clearance_level >= 4:
            return True, f"Clearance level: {user.clearance_level}"
        return False, f"Requires finance dept or clearance ≥ 4. You: {user.department}, level {user.clearance_level}"

    @staticmethod
    def can_access_adult_content(user: User) -> tuple[bool, str]:
        """Age-based: user must be 18+."""
        if user.age >= 18:
            return True, f"Age verified: {user.age}"
        return False, f"Must be 18+. Your age: {user.age}"

    @staticmethod
    def can_access_us_content(user: User) -> tuple[bool, str]:
        """Geo-restriction: US only."""
        if user.country == "US":
            return True, f"Country: {user.country}"
        return False, f"US users only. Your country: {user.country}"

    @staticmethod
    def can_access_premium_features(user: User) -> tuple[bool, str]:
        """Membership-based access."""
        allowed = {"premium", "enterprise"}
        if user.membership_status in allowed:
            return True, f"Membership: {user.membership_status}"
        return False, f"Premium/Enterprise required. Your plan: {user.membership_status}"

    @staticmethod
    def can_access_engineering_tools(user: User) -> tuple[bool, str]:
        """Engineering tools: department=engineering AND clearance >= 2."""
        if user.department == "engineering" and user.clearance_level >= 2:
            return True, f"Engineering dept, clearance {user.clearance_level}"
        return False, f"Requires engineering dept + clearance ≥ 2. You: {user.department}, level {user.clearance_level}"

    @staticmethod
    def evaluate_all(user: User) -> dict:
        """Evaluate all ABAC policies for a user — used for the demo matrix."""
        policies = {
            "financial_reports": ABACPolicy.can_access_financial_reports(user),
            "adult_content": ABACPolicy.can_access_adult_content(user),
            "us_geo_restricted": ABACPolicy.can_access_us_content(user),
            "premium_features": ABACPolicy.can_access_premium_features(user),
            "engineering_tools": ABACPolicy.can_access_engineering_tools(user),
        }
        return {
            name: {"allowed": result[0], "reason": result[1]}
            for name, result in policies.items()
        }


# ─────────────────────────────────────────────────────────────
# RESOURCE OWNERSHIP
# ─────────────────────────────────────────────────────────────

def check_resource_owner(
    resource_owner_id: int,
    current_user: User,
    session: Session,
    allow_roles: tuple = ("admin", "moderator"),
) -> bool:
    """
    Check if the current user owns a resource, OR has an elevated role.

    IDOR prevention: users should only modify their own resources.
    Admins/mods can override this.

    Example:
        post = get_post(post_id)
        if not check_resource_owner(post.owner_id, current_user, session):
            raise HTTPException(403, "You can only edit your own posts")
    """
    # Resource owner always has access
    if resource_owner_id == current_user.id:
        return True

    # Check if user has a bypass role
    role = session.get(Role, current_user.role_id)
    if role and role.name in allow_roles:
        return True

    return False


def get_user_role(user: User, session: Session) -> Optional[Role]:
    """Helper: fetch the Role object for a user."""
    return session.get(Role, user.role_id)


def get_user_permissions(user: User, session: Session) -> list[str]:
    """Fetch all permission names for a user's role."""
    role_perms = session.exec(
        select(RolePermission).where(RolePermission.role_id == user.role_id)
    ).all()
    perms = []
    for rp in role_perms:
        perm = session.get(Permission, rp.permission_id)
        if perm:
            perms.append(perm.name)
    return perms
