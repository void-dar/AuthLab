"""
Demo Router — Fixed
All interactive educational demonstrations.
"""
import secrets
import hashlib
import json
import math
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from pydantic import BaseModel
from sqlmodel import Session, select

from app.database.db import get_session
from app.auth.hashing import demo_hash_password, analyze_password_strength, verify_password, hash_password
from app.auth.tokens import decode_jwt_educational, create_demo_tampered_token, create_access_token
from app.auth.dependencies import get_current_user, get_current_user_optional, ABACPolicy, get_user_permissions
from app.models.models import (
    User, Role, Post, OAuthClient, OAuthAuthCode,
    OTPCode, PasswordResetToken, MagicLinkToken, SSOSession
)
from app.services.auth_service import (
    generate_otp, verify_otp, generate_password_reset_token,
    reset_password, generate_magic_link, verify_magic_link,
    authenticate_user, log_event
)
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/demo", tags=["demos"])


def utcnow():
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────
# PASSWORD HASHING DEMO
# ─────────────────────────────────────────────────────────────

class HashRequest(BaseModel):
    password: str


@router.post("/hash")
async def demo_hash(data: HashRequest):
    """Hash a password with multiple algorithms for comparison."""
    pwd = data.password[:72]  # safe bcrypt cap

    results = {}

    # MD5
    t0 = time.perf_counter()
    md5_hash = hashlib.md5(pwd.encode()).hexdigest()
    results["md5"] = {
        "hash": md5_hash,
        "time_ms": round((time.perf_counter() - t0) * 1000, 4),
        "security": "BROKEN",
        "note": "No salt, instant GPU cracking. NEVER use for passwords."
    }

    # SHA-256
    t0 = time.perf_counter()
    sha256_hash = hashlib.sha256(pwd.encode()).hexdigest()
    results["sha256"] = {
        "hash": sha256_hash,
        "time_ms": round((time.perf_counter() - t0) * 1000, 4),
        "security": "INSECURE",
        "note": "Fast = bad for passwords. No salt, no cost factor."
    }

    # SHA-256 + salt
    salt = secrets.token_hex(16)
    t0 = time.perf_counter()
    salted_hash = hashlib.sha256((salt + pwd).encode()).hexdigest()
    results["sha256_salted"] = {
        "hash": f"${salt}${salted_hash}",
        "time_ms": round((time.perf_counter() - t0) * 1000, 4),
        "security": "WEAK",
        "note": "Salt prevents rainbow tables but still too fast for GPU brute force."
    }

    # bcrypt — use bcrypt_lib directly to avoid passlib 72-byte bug
    try:
        import bcrypt as bcrypt_lib
        t0 = time.perf_counter()
        bc_salt = bcrypt_lib.gensalt(rounds=12)
        bcrypt_hash = bcrypt_lib.hashpw(pwd.encode(), bc_salt).decode()
        results["bcrypt"] = {
            "hash": bcrypt_hash,
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security": "GOOD",
            "note": "Deliberately slow (rounds=12). Built-in salt. Still memory-light — GPU attacks possible."
        }
    except Exception as e:
        results["bcrypt"] = {
            "hash": f"[bcrypt error: {str(e)[:40]}]",
            "time_ms": 0,
            "security": "GOOD",
            "note": "bcrypt: deliberately slow, built-in salt."
        }

    # Argon2id
    from passlib.context import CryptContext
    argon2_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
    t0 = time.perf_counter()
    argon2_hash = argon2_ctx.hash(pwd)
    results["argon2id"] = {
        "hash": argon2_hash,
        "time_ms": round((time.perf_counter() - t0) * 1000, 1),
        "security": "BEST",
        "note": "Memory-hard (64MB RAM per hash). PHC winner 2015. GPU farms defeated."
    }

    # Analysis observations
    analysis = [
        f"MD5 took {results['md5']['time_ms']}ms vs Argon2id {results['argon2id']['time_ms']}ms — that slowness is intentional!",
        "All Argon2 hashes are different even with the same password (unique salt each time)",
        "bcrypt hashes start with $2b$ — the format encodes the algorithm, cost factor, and salt",
        "Argon2id hashes start with $argon2id$ — parameters are embedded in the hash string",
        "On a GPU: 10 billion MD5/second vs ~5 Argon2id/second — ~2 billion times harder to brute force",
    ]

    strength = analyze_password_strength(pwd)
    # Normalize score to 0-4 for frontend
    score_0_100 = strength.get("score", 0)
    score_0_4 = min(4, score_0_100 // 20)

    return {
        "algorithms": results,
        "analysis": analysis,
        "strength": {
            "score": score_0_4,
            "score_pct": score_0_100,
            "level": strength.get("level", ""),
            "entropy": strength.get("entropy_bits"),
            "length": len(pwd),
            "feedback": strength.get("issues", []),
            "crack_time": "< 1 second (GPU)" if score_0_4 < 2 else "centuries (Argon2id)" if score_0_4 >= 3 else "hours to days (Argon2id)"
        }
    }


@router.post("/password-strength")
async def check_password_strength(data: HashRequest):
    """Analyze password strength in real-time — returns 0-4 score for frontend."""
    pwd = data.password
    result = analyze_password_strength(pwd)

    score_100 = result.get("score", 0)
    score_4 = min(4, score_100 // 20)

    # Crack time estimate
    charset_size = result.get("charset_size", 26)
    length = result.get("length", len(pwd))
    entropy = result.get("entropy_bits", 0)
    if entropy > 80:
        crack_time = "Centuries (with Argon2id)"
    elif entropy > 60:
        crack_time = "Years"
    elif entropy > 40:
        crack_time = "Hours to days"
    elif entropy > 20:
        crack_time = "Minutes"
    else:
        crack_time = "< 1 second"

    return {
        "score": score_4,
        "score_pct": score_100,
        "level": result.get("level", ""),
        "entropy": result.get("entropy_bits"),
        "length": length,
        "feedback": result.get("issues", []),
        "crack_time": crack_time,
    }


# ─────────────────────────────────────────────────────────────
# JWT DEMO
# ─────────────────────────────────────────────────────────────

@router.post("/jwt/decode")
async def jwt_decode(request: Request):
    """Educational JWT decoder."""
    body = await request.json()
    token = body.get("token", "")
    if not token:
        raise HTTPException(400, "No token provided")
    return decode_jwt_educational(token)


@router.get("/jwt/create-demo")
async def create_demo_jwt(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Generate a fresh JWT for inspection."""
    role = session.get(Role, current_user.role_id)
    token, expiry = create_access_token(
        user_id=current_user.id,
        username=current_user.username,
        role=role.name if role else "user",
        extra_claims={"demo": True}
    )
    decoded = decode_jwt_educational(token)
    return {
        "token": token,
        "decoded": decoded,
        "educational_notes": [
            "The payload is NOT encrypted — anyone can read it. Never put secrets in JWT payload.",
            "Only the SIGNATURE is protected by the server secret key.",
            "Tampering with header or payload invalidates the signature.",
            "This token expires in 15 minutes (short lifetime = less damage if stolen).",
        ]
    }


@router.post("/jwt/tamper")
async def jwt_tamper_demo(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    ATTACK DEMO: Generate a real token, then tamper with it.
    Shows that signature validation blocks the tampered token.
    """
    role = session.get(Role, current_user.role_id)
    # Create a real token for this user (role = user)
    original_token, _ = create_access_token(
        user_id=current_user.id,
        username=current_user.username,
        role="user",  # force non-admin to show escalation attempt
    )

    # Now tamper: change payload to claim admin role
    result = create_demo_tampered_token(original_token)

    return {
        "original_token": original_token,
        "tampered_token": result.get("tampered_token", ""),
        "tamper_detected": result.get("tamper_detected", True),
        "explanation": result.get("explanation", "Signature mismatch detected — tampered token rejected."),
        "educational": {
            "what_happened": "We modified the payload to escalate role to 'admin' but kept the original signature.",
            "why_it_fails": "The signature is HMAC-SHA256(secret, header.payload). Changing payload invalidates the signature.",
            "alg_none_attack": "Some old JWT libraries accept 'alg: none' — always validate the algorithm explicitly.",
        }
    }


# ─────────────────────────────────────────────────────────────
# MFA / OTP DEMO
# ─────────────────────────────────────────────────────────────

class MFAGenerateRequest(BaseModel):
    username: str


@router.post("/mfa/generate")
async def mfa_generate_otp(
    data: MFAGenerateRequest,
    session: Session = Depends(get_session),
):
    """Generate a simulated OTP. Returns the code directly for demo visibility."""
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user:
        raise HTTPException(404, f"User '{data.username}' not found")

    code = generate_otp(session, user.id, purpose="demo")
    return {
        "otp": code,
        "username": user.username,
        "expires_in": settings.OTP_EXPIRE_MINUTES * 60,
        "educational": {
            "warning": "In production, the OTP is NEVER returned in the API response — it's sent via SMS or email!",
            "how_totp_works": "TOTP = HMAC-SHA1(shared_secret + time_step). Both server and authenticator app compute the same value.",
            "single_use": "Each OTP is single-use. After verification (success or failure), it's invalidated.",
        }
    }


class OTPVerifyRequest(BaseModel):
    username: str
    code: str


@router.post("/mfa/verify")
async def mfa_verify_otp(
    data: OTPVerifyRequest,
    session: Session = Depends(get_session),
):
    """Verify an OTP code."""
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user:
        raise HTTPException(404, f"User '{data.username}' not found")

    valid = verify_otp(session, user.id, data.code, purpose="demo")
    return {
        "valid": valid,
        "message": "✅ OTP verified successfully! MFA passed." if valid else "❌ Invalid or expired OTP.",
        "educational": {
            "single_use": "OTPs are single-use — this code is now consumed.",
            "time_limit": f"OTPs expire after {settings.OTP_EXPIRE_MINUTES} minutes.",
            "brute_force_defense": "Rate-limit OTP attempts. Lock after N wrong guesses.",
        }
    }


# ─────────────────────────────────────────────────────────────
# PASSWORD RESET DEMO
# ─────────────────────────────────────────────────────────────

class PasswordResetRequestSchema(BaseModel):
    username: str  # accept username for demo simplicity


@router.post("/password-reset/request")
async def request_password_reset(
    data: PasswordResetRequestSchema,
    session: Session = Depends(get_session),
):
    """Request a password reset token (simulated — no email sent)."""
    # Look up user by username
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user:
        # Don't reveal whether user exists
        return {
            "message": "If an account with that username exists, a reset link has been sent.",
            "educational": {
                "enumeration_prevention": "We return the same message whether user exists or not — prevents user enumeration attacks.",
            }
        }

    raw_token = generate_password_reset_token(session, user.email)
    if not raw_token:
        return {"message": "If an account with that username exists, a reset link has been sent."}

    reset_url = f"http://localhost:8000/demo/passwordless?token={raw_token}"
    return {
        "message": "Password reset token generated (normally sent via email)",
        "reset_token": raw_token,
        "reset_url": reset_url,
        "expires_in": settings.PASSWORD_RESET_EXPIRE_MINUTES * 60,
        "educational": {
            "in_production": "This token would be emailed as a link. Never expose it in the response.",
            "token_security": "Token is secrets.token_urlsafe(32) — 256 bits of entropy. Hashed before storage.",
            "single_use": "Token is deleted after first use.",
        }
    }


class PasswordResetCompleteSchema(BaseModel):
    token: str
    new_password: str


@router.post("/password-reset/complete")
async def complete_password_reset(
    data: PasswordResetCompleteSchema,
    session: Session = Depends(get_session),
):
    """Complete a password reset using the token."""
    success = reset_password(session, data.token, data.new_password)
    if not success:
        raise HTTPException(400, "Invalid or expired reset token")
    return {
        "success": True,
        "message": "Password has been reset successfully",
        "educational": {
            "next_steps": "In production: invalidate ALL existing sessions after password reset.",
            "why": "Active sessions may belong to the attacker — all must be terminated on password change.",
        }
    }


# ─────────────────────────────────────────────────────────────
# MAGIC LINK DEMO
# ─────────────────────────────────────────────────────────────

class MagicLinkRequest(BaseModel):
    username: str  # accept username for demo simplicity


@router.post("/magic-link/request")
async def request_magic_link(
    data: MagicLinkRequest,
    session: Session = Depends(get_session),
):
    """Generate a magic link for passwordless authentication."""
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user:
        return {"message": "If that user exists, a magic link has been sent."}

    result = generate_magic_link(session, user.email)
    if not result:
        return {"message": "If that user exists, a magic link has been sent."}

    raw_token, user = result
    magic_url = f"http://localhost:8000/api/demo/magic-link/verify?token={raw_token}"

    return {
        "message": "Magic link generated (normally sent via email)",
        "token": raw_token,
        "magic_url": magic_url,
        "expires_in": settings.MAGIC_LINK_EXPIRE_MINUTES * 60,
        "username": user.username,
        "educational": {
            "what_is_magic_link": "A one-time URL sent to user's email. Clicking it logs them in — no password needed.",
            "single_use": "Link is invalidated after first use — replay attacks prevented.",
            "security_basis": "Security depends on email account security. Strong email = strong auth.",
            "companies_using": "Slack, Medium, Notion use magic links as primary login.",
        }
    }


@router.get("/magic-link/verify")
async def verify_magic_link_endpoint(
    token: str,
    response: Response,
    session: Session = Depends(get_session),
):
    """Verify a magic link and issue session."""
    user = verify_magic_link(session, token)
    if not user:
        raise HTTPException(400, "Invalid or expired magic link")

    role = session.get(Role, user.role_id)
    access_token, expiry = create_access_token(
        user_id=user.id, username=user.username,
        role=role.name if role else "user"
    )
    response.set_cookie("access_token", access_token, httponly=True, samesite="lax")

    return {
        "success": True,
        "username": user.username,
        "message": f"Authenticated via magic link as {user.username}. Token consumed — cannot be reused.",
    }


# ─────────────────────────────────────────────────────────────
# ABAC DEMO
# ─────────────────────────────────────────────────────────────

@router.get("/abac/evaluate")
async def abac_evaluate(
    username: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Evaluate all ABAC policies for a specific user (defaults to current user)."""
    # If username provided and current user is admin, evaluate that user
    target_user = current_user
    if username and username != current_user.username:
        found = session.exec(select(User).where(User.username == username)).first()
        if found:
            target_user = found

    evaluation = ABACPolicy.evaluate_all(target_user)

    # evaluation is a dict: {policy_name: {allowed: bool, reason: str}}
    # Define human-readable rules
    policy_rules = {
        "financial_reports": 'department == "Finance" AND clearance_level >= 3',
        "adult_content": "age >= 18",
        "us_geo_restricted": 'country == "US"',
        "premium_features": 'membership_status == "premium"',
        "engineering_tools": 'department IN ["Engineering", "DevOps"] AND clearance_level >= 2',
    }

    policies_list = [
        {
            "policy_name": name.replace("_", " ").title(),
            "rule": policy_rules.get(name, ""),
            "allowed": info.get("allowed", False),
            "reason": info.get("reason", ""),
        }
        for name, info in evaluation.items()
    ]

    role = session.get(Role, target_user.role_id)
    permissions = get_user_permissions(target_user, session)

    return {
        "user_attributes": {
            "username": target_user.username,
            "role": role.name if role else "unknown",
            "department": target_user.department,
            "clearance_level": target_user.clearance_level,
            "age": target_user.age,
            "country": target_user.country,
            "membership_status": target_user.membership_status,
        },
        "policies": policies_list,
        "rbac_permissions": permissions,
        "educational": {
            "rbac_vs_abac": "RBAC grants permissions by role (static). ABAC evaluates dynamic conditions at runtime.",
            "use_case": "ABAC excels when roles alone can't express fine-grained access rules.",
        }
    }


# ─────────────────────────────────────────────────────────────
# RESOURCE OWNERSHIP (RBAC DEMO)
# ─────────────────────────────────────────────────────────────

@router.get("/posts")
async def list_posts(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """List posts with ownership metadata for RBAC demo."""
    posts = session.exec(select(Post)).all()
    role = session.get(Role, current_user.role_id)
    role_name = role.name if role else "user"

    post_list = []
    for post in posts:
        owner = session.get(User, post.owner_id)
        can_edit = (post.owner_id == current_user.id) or (role_name in ("admin", "moderator"))
        post_list.append({
            "id": post.id,
            "title": post.title,
            "author_username": owner.username if owner else "unknown",
            "is_mine": post.owner_id == current_user.id,
            "can_edit": can_edit,
        })

    return {
        "posts": post_list,
        "your_role": role_name,
        "note": f"As '{role_name}', you {'can edit any post' if role_name in ('admin','moderator') else 'can only edit your own posts'}.",
        "educational": {
            "ownership_check": "post.owner_id == current_user.id",
            "admin_override": "Admins and moderators bypass ownership checks (privileged access)",
            "idor_warning": "Without this check, any user could edit any post by guessing IDs",
        }
    }


@router.put("/posts/{post_id}")
async def update_post(
    post_id: int,
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Update a post — enforces RBAC ownership check."""
    post = session.get(Post, post_id)
    if not post:
        raise HTTPException(404, "Post not found")

    role = session.get(Role, current_user.role_id)
    role_name = role.name if role else "user"
    is_owner = post.owner_id == current_user.id
    is_privileged = role_name in ("admin", "moderator")

    if not is_owner and not is_privileged:
        raise HTTPException(
            403,
            f"Access denied. You don't own this post. "
            f"(Your ID: {current_user.id}, Owner ID: {post.owner_id})"
        )

    body = await request.json()
    if "title" in body:
        post.title = body["title"]
    if "content" in body:
        post.content = body["content"]
    post.updated_at = utcnow()
    session.add(post)
    session.commit()

    return {
        "success": True,
        "post": {"id": post.id, "title": post.title},
        "authorized_via": "ownership" if is_owner else f"role privilege ({role_name})",
    }


# ─────────────────────────────────────────────────────────────
# OAUTH 2.0 SIMULATION
# ─────────────────────────────────────────────────────────────

@router.get("/oauth/authorize")
async def oauth_authorize(
    client_id: str,
    scope: str = "openid profile email",
    state: str = "",
    response_type: str = "code",
    redirect_uri: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """OAuth 2.0 Authorization Endpoint — issues authorization code."""
    # Accept any demo-client-123 client (create if needed for demo)
    client = session.exec(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    ).first()

    # For demo, auto-register unknown clients
    if not client:
        demo_redirect = redirect_uri or "http://localhost:8000/demo/oauth/callback"
        client = OAuthClient(
            client_id=client_id,
            client_secret_hash=hash_password("demo-secret"),
            name=f"Demo Client ({client_id})",
            description="Auto-registered demo OAuth client",
            redirect_uri=demo_redirect,
            allowed_scopes="openid profile email",
        )
        session.add(client)
        session.commit()
        session.refresh(client)

    effective_redirect = redirect_uri or client.redirect_uri

    # Issue authorization code
    code = secrets.token_urlsafe(32)
    expire = utcnow() + timedelta(seconds=settings.OAUTH_AUTH_CODE_EXPIRE_SECONDS)

    auth_code = OAuthAuthCode(
        code=code,
        client_id=client_id,
        user_id=current_user.id,
        scope=scope,
        redirect_uri=effective_redirect,
        expires_at=expire,
    )
    session.add(auth_code)
    session.commit()

    return {
        "auth_url": f"{effective_redirect}?code={code}&state={state}",
        "auth_code": code,
        "params": {
            "client_id": client_id,
            "scope": scope,
            "state": state,
            "response_type": response_type,
        },
        "expires_in_seconds": settings.OAUTH_AUTH_CODE_EXPIRE_SECONDS,
        "educational": {
            "flow": "Authorization Code Flow: User consents → Auth Server issues code → Client exchanges code for tokens",
            "why_code": "Code is exchanged server-to-server — tokens never exposed in browser URL/history.",
            "state_param": "The 'state' parameter prevents CSRF attacks during the OAuth flow.",
            "pkce": "Modern OAuth adds PKCE (Proof Key for Code Exchange) to prevent code interception.",
        }
    }


@router.post("/oauth/token")
async def oauth_token_exchange(
    request: Request,
    session: Session = Depends(get_session),
):
    """OAuth 2.0 Token Endpoint — exchanges code for tokens."""
    body = await request.json()
    code = body.get("code")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret", "demo-secret")

    if not code or not client_id:
        raise HTTPException(400, "Missing code or client_id")

    auth_code = session.exec(
        select(OAuthAuthCode).where(
            OAuthAuthCode.code == code,
            OAuthAuthCode.client_id == client_id,
            OAuthAuthCode.is_used == False,
        )
    ).first()
    now = utcnow().replace(tzinfo=None)
    if not auth_code or now > auth_code.expires_at:
        raise HTTPException(400, "Invalid or expired authorization code")

    # Verify client
    client = session.exec(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    ).first()
    if not client:
        raise HTTPException(401, "Unknown client")

    # Mark code as used
    auth_code.is_used = True
    session.add(auth_code)

    user = session.get(User, auth_code.user_id)
    role = session.get(Role, user.role_id) if user else None

    access_token, expiry = create_access_token(
        user_id=user.id,
        username=user.username,
        role=role.name if role else "user",
        extra_claims={"scope": auth_code.scope, "client_id": client_id}
    )

    session.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "scope": auth_code.scope,
        "user_info": {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "name": user.full_name,
        },
        "id_token": f"[OIDC ID Token would be here — contains: sub={user.id}, email={user.email}]",
        "educational": {
            "oauth_vs_oidc": "OAuth provides authorization (access token). OIDC adds authentication (ID token).",
            "code_is_single_use": "Authorization codes are single-use and short-lived.",
            "server_to_server": "Token exchange happens server-to-server, keeping tokens out of the browser.",
        }
    }


# ─────────────────────────────────────────────────────────────
# SSO SIMULATION
# ─────────────────────────────────────────────────────────────

class SSOLoginRequest(BaseModel):
    username: str
    password: str


@router.post("/sso/login")
async def sso_login(
    data: SSOLoginRequest,
    session: Session = Depends(get_session),
):
    """Authenticate and create a central SSO session."""
    # authenticate_user returns (user, access_token, refresh_token, expiry) or raises HTTPException
    result = authenticate_user(session, data.username, data.password)
    user = result[0]  # first element is always the User object

    sso_token = secrets.token_urlsafe(32)
    expire = utcnow() + timedelta(hours=8)

    sso_session = SSOSession(
        sso_token=sso_token,
        user_id=user.id,
        apps_accessed=json.dumps(["AuthLab (Identity Provider)"]),
        expires_at=expire,
    )
    session.add(sso_session)
    session.commit()

    return {
        "sso_token": sso_token,
        "username": user.username,
        "expires_in": 8 * 3600,
        "message": "SSO session created. Access Inventory or Payroll without re-logging in.",
        "educational": {
            "how_sso_works": "User authenticates once with the IdP. The IdP issues an SSO token. Each app validates with the IdP — no re-login needed.",
            "protocols": "Enterprise SSO uses SAML 2.0 or OpenID Connect.",
            "single_logout": "With SSO, logging out of one app can terminate ALL sessions simultaneously (SLO).",
        }
    }


@router.get("/sso/access/{app_name}")
async def sso_access_app(
    app_name: str,
    sso_token: str,
    session: Session = Depends(get_session),
):
    """Access a second app via SSO — no re-login required."""
    valid_apps = ["inventory", "payroll"]
    if app_name not in valid_apps:
        raise HTTPException(400, f"Unknown app. Valid: {valid_apps}")

    sso_session = session.exec(
        select(SSOSession).where(
            SSOSession.sso_token == sso_token,
            SSOSession.is_active == True,
        )
    ).first()

    if not sso_session or datetime.now() > sso_session.expires_at.replace(tzinfo=None):
        raise HTTPException(401, "Invalid or expired SSO session. Please log in again.")

    user = session.get(User, sso_session.user_id)
    apps = json.loads(sso_session.apps_accessed)
    app_display = f"{app_name.title()} System"

    if app_display not in apps:
        apps.append(app_display)
        sso_session.apps_accessed = json.dumps(apps)
        session.add(sso_session)
        session.commit()

    app_data = {
        "inventory": {"message": "Showing 142 products across 3 warehouses. Last sync: 2 min ago."},
        "payroll": {"message": "Payroll for June 2026 processed. Next run: July 1st."},
    }

    return {
        "access_granted": True,
        "app": app_display,
        "username": user.username if user else "unknown",
        "apps_accessed_this_session": apps,
        "app_data": app_data.get(app_name, {}),
        "educational": {
            "sso_benefit": f"No re-login required. Same session now covers: {', '.join(apps)}.",
            "logout": "Single Logout (SLO) terminates ALL sessions simultaneously.",
        }
    }


# ─────────────────────────────────────────────────────────────
# ATTACK DEMOS
# ─────────────────────────────────────────────────────────────

class SQLInjectionDemo(BaseModel):
    username: str
    secure: bool = False


@router.post("/attack/sql-injection")
async def sql_injection_demo(
    data: SQLInjectionDemo,
    session: Session = Depends(get_session),
):
    """Educational SQL injection vs parameterized query demo."""
    username = data.username
    # Simulated password field for query construction
    password_placeholder = "anypassword"

    vulnerable_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_placeholder}'"

    injection_keywords = ["'", "--", " OR ", "1=1", "DROP", "UNION", ";", "/*"]
    looks_like_injection = any(kw.upper() in username.upper() for kw in injection_keywords)

    if data.secure:
        # Safe path: parameterized query
        actual_user = session.exec(select(User).where(User.username == username)).first()
        return {
            "mode": "SECURE (parameterized query)",
            "bypassed": False,
            "message": f"Parameterized query safely handled input. User found: {actual_user.username if actual_user else 'None'}",
            "executed_query": "SELECT * FROM users WHERE username = ? [parameter bound separately]",
            "looks_like_injection": looks_like_injection,
            "educational": "SQLModel/SQLAlchemy always uses parameterized queries. User input is never interpolated into SQL."
        }
    else:
        # Vulnerable path: string concatenation
        bypassed = looks_like_injection
        return {
            "mode": "VULNERABLE (string concatenation)",
            "bypassed": bypassed,
            "message": (
                f"⚠️ VULNERABLE! Injection payload '{username}' would bypass authentication!"
                if bypassed else
                f"Input '{username}' appears safe this time — but the query is still dangerous!"
            ),
            "executed_query": vulnerable_query,
            "looks_like_injection": looks_like_injection,
            "educational": "This query concatenates user input directly into SQL. ' OR '1'='1 would return ALL rows — auth bypass!"
        }


@router.get("/attack/brute-force-simulation")
async def brute_force_simulation():
    """Visualize a brute-force attack with defense mechanisms."""
    attempts = [
        {"attempt": 1, "password": "password", "blocked": False, "reason": "Attempt 1/5 allowed"},
        {"attempt": 2, "password": "123456", "blocked": False, "reason": "Attempt 2/5 allowed"},
        {"attempt": 3, "password": "admin123", "blocked": False, "reason": "Attempt 3/5 allowed"},
        {"attempt": 4, "password": "letmein", "blocked": False, "reason": "Attempt 4/5 allowed"},
        {"attempt": 5, "password": "qwerty", "blocked": False, "reason": "Attempt 5/5 allowed"},
        {"attempt": 6, "password": "pass1234", "blocked": True, "reason": "🔒 LOCKED: 5 failed attempts → account locked for 15 min"},
        {"attempt": 7, "password": "test123", "blocked": True, "reason": "🔒 LOCKED: Account still locked"},
        {"attempt": 8, "password": "abc123", "blocked": True, "reason": "🔒 RATE LIMITED: Too many requests from this IP"},
        {"attempt": 9, "password": "welcome1", "blocked": True, "reason": "🔒 RATE LIMITED: IP blocked for 1 hour"},
        {"attempt": 10, "password": "correct_password!", "blocked": True, "reason": "🔒 Would have succeeded but account is locked!"},
    ]

    return {
        "scenario": "Attacker tries common passwords against account 'alice'",
        "attempts": attempts,
        "summary": (
            "Defenses activated after attempt 5: account lockout + rate limiting blocked all further attempts. "
            "Even the correct password on attempt 10 was blocked — lockout protects even if password is weak!"
        ),
        "defenses_demonstrated": [
            "Account lockout (5 attempts → 15min lock)",
            "Rate limiting (5 req/min per IP)",
            "Progressive delay (each failure adds wait time)",
            "Argon2id makes each guess ~200ms even with leaked hash",
        ],
        "educational": {
            "without_defenses": "10 billion MD5 hashes/sec on GPU → 6-char password cracked in seconds",
            "with_argon2": "200ms + 64MB per Argon2id guess → GPU farm attack takes centuries",
            "real_world": "2012 LinkedIn breach: 60% of unsalted SHA-1 hashes cracked in hours. Argon2 would still be safe.",
        }
    }


@router.post("/attack/insecure-direct-reference")
async def idor_demo(
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """IDOR Demo: accessing resources without ownership check."""
    body = await request.json()
    target_user_id = body.get("target_user_id", body.get("post_id", 1))
    secure = body.get("secure", False)

    # Find a post owned by the target user
    post = session.exec(
        select(Post).where(Post.owner_id == target_user_id)
    ).first()

    if not post:
        # Fall back to any post
        post = session.exec(select(Post)).first()

    if not post:
        raise HTTPException(404, "No posts found")

    owner = session.get(User, post.owner_id)
    is_owner = post.owner_id == current_user.id

    if secure and not is_owner:
        return {
            "data_exposed": False,
            "message": f"✅ ACCESS DENIED — Ownership check blocked the request. Post belongs to {owner.username if owner else '?'}, not {current_user.username}.",
            "educational": "The secure endpoint checks post.owner_id == current_user.id before returning data."
        }

    return {
        "data_exposed": not is_owner,
        "message": (
            f"✅ You own this post — access granted."
            if is_owner else
            f"⚠️ IDOR: You accessed post owned by '{owner.username if owner else '?'}' — not you! Without an ownership check, any user can see/edit any resource by guessing its ID."
        ),
        "post": {
            "id": post.id,
            "title": post.title,
            "owner": owner.username if owner else "unknown",
            "owner_id": post.owner_id,
        },
        "current_user": {"id": current_user.id, "username": current_user.username},
        "is_owner": is_owner,
        "educational": {
            "what_is_idor": "IDOR: Accessing objects by ID without checking authorization. #1 web vulnerability category.",
            "fix": "Always verify: current_user.id == resource.owner_id (or admin override).",
            "owasp": "OWASP A01:2021 — Broken Access Control.",
        }
    }
