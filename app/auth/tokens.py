"""
JWT Token Management
====================
Implements Access Tokens, Refresh Tokens, and educational JWT decoding.

ANATOMY OF A JWT
================
A JWT has three base64url-encoded parts separated by dots:

    HEADER.PAYLOAD.SIGNATURE

Header:  {"alg": "HS256", "typ": "JWT"}
         Tells the verifier WHICH algorithm was used.

Payload: {"sub": "42", "role": "user", "exp": 1720000000, ...}
         The "claims" — data you're asserting. NEVER put secrets here.
         Base64 is NOT encryption — anyone can decode it!

Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
           This is what makes JWTs tamper-proof. Without the secret,
           you can't forge a valid signature.

COMMON VULNERABILITIES:
- "alg: none" attack: attacker strips signature, sets alg to "none"
- Algorithm confusion: RS256 key used as HS256 secret
- Sensitive data in payload (SSNs, passwords — never do this!)
- Long expiry times (access tokens should be 5-15 minutes)
"""
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import base64
import json

from jose import JWTError, jwt
from app.config import get_settings

settings = get_settings()


# ─────────────────────────────────────────────────────────────
# TOKEN CREATION
# ─────────────────────────────────────────────────────────────

def create_access_token(
    user_id: int,
    username: str,
    role: str,
    extra_claims: dict = None
) -> tuple[str, datetime]:
    """
    Create a short-lived JWT access token.
    Returns (token_string, expiry_datetime).
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        # Standard JWT claims (RFC 7519)
        "sub": str(user_id),          # Subject: who the token represents
        "iat": now,                    # Issued At
        "exp": expire,                 # Expiration Time
        "nbf": now,                    # Not Before
        "iss": settings.JWT_ISSUER,   # Issuer
        "aud": settings.JWT_AUDIENCE, # Audience
        "jti": secrets.token_hex(16), # JWT ID: unique per token (enables revocation tracking)

        # Application claims
        "username": username,
        "role": role,
        "token_type": "access",
    }

    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expire


def create_refresh_token(user_id: int, family: str = None) -> tuple[str, str, datetime]:
    """
    Create a long-lived refresh token.
    Returns (raw_token, token_hash, expiry_datetime).

    The raw token is sent to the client.
    The hash is stored in DB (never store raw tokens in DB).

    Token families enable refresh token rotation — if a revoked token
    is used, the entire family is invalidated (detects theft).
    """
    if not family:
        family = secrets.token_hex(16)

    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    return raw_token, token_hash, expire


# ─────────────────────────────────────────────────────────────
# TOKEN VALIDATION
# ─────────────────────────────────────────────────────────────

def verify_access_token(token: str) -> Optional[dict]:
    """
    Validate and decode a JWT access token.
    Returns payload dict if valid, None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("token_type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ─────────────────────────────────────────────────────────────
# EDUCATIONAL JWT DECODER
# ─────────────────────────────────────────────────────────────

def decode_jwt_educational(token: str) -> dict:
    """
    Decode a JWT for educational visualization without verifying the signature.
    Shows exactly what's inside each part.

    IMPORTANT: This is for DISPLAY ONLY.
    Never use unverified JWT claims for authorization decisions!
    """
    result = {
        "valid_format": False,
        "header": None,
        "payload": None,
        "signature": None,
        "signature_verified": False,
        "raw_parts": {},
        "analysis": {},
        "error": None,
    }

    parts = token.split(".")
    if len(parts) != 3:
        result["error"] = "Invalid JWT format: expected 3 parts separated by dots"
        return result

    result["valid_format"] = True
    result["raw_parts"] = {
        "header": parts[0],
        "payload": parts[1],
        "signature": parts[2],
    }

    def _decode_b64(s: str) -> dict:
        """Decode base64url-encoded JSON."""
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        try:
            raw = base64.urlsafe_b64decode(s)
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    result["header"] = _decode_b64(parts[0])
    result["payload"] = _decode_b64(parts[1])
    result["signature"] = parts[2]

    # Verify signature
    try:
        jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_aud": False, "verify_iss": False}
        )
        result["signature_verified"] = True
    except JWTError as e:
        result["signature_verified"] = False
        result["signature_error"] = str(e)

    # Analysis
    payload = result["payload"] or {}
    now_ts = datetime.now(timezone.utc).timestamp()

    analysis = {
        "algorithm": result["header"].get("alg") if result["header"] else None,
        "token_type": payload.get("token_type", "unknown"),
        "subject": payload.get("sub"),
        "username": payload.get("username"),
        "role": payload.get("role"),
        "issuer": payload.get("iss"),
        "audience": payload.get("aud"),
    }

    if "exp" in payload:
        exp_ts = payload["exp"]
        exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
        analysis["expires_at"] = exp_dt.isoformat()
        analysis["is_expired"] = now_ts > exp_ts
        analysis["seconds_until_expiry"] = max(0, int(exp_ts - now_ts))

    if "iat" in payload:
        iat_dt = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        analysis["issued_at"] = iat_dt.isoformat()

    result["analysis"] = analysis

    # Security warnings
    warnings = []
    if result["header"] and result["header"].get("alg") == "none":
        warnings.append("🚨 CRITICAL: Algorithm is 'none' — signature bypass attack!")
    if result["header"] and result["header"].get("alg", "").startswith("RS") and \
       "secret" in settings.SECRET_KEY.lower():
        warnings.append("⚠️ Algorithm confusion risk: RS* algorithm with symmetric key")
    if payload.get("exp", 0) - payload.get("iat", 0) > 86400:
        warnings.append("⚠️ Token lifetime exceeds 24 hours — consider shorter expiry")
    if "password" in str(payload).lower() or "secret" in str(payload).lower():
        warnings.append("🚨 Possible sensitive data in payload — JWTs are not encrypted!")

    result["security_warnings"] = warnings

    return result


def create_demo_tampered_token(original_token: str) -> dict:
    """
    Educational demo: show what happens when you tamper with a JWT.
    Attempts to change role to 'admin' in the payload.
    Returns both the tampered token and what happens when verified.
    """
    parts = original_token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid token"}

    def decode_b64(s):
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return json.loads(base64.urlsafe_b64decode(s))

    def encode_b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    payload = decode_b64(parts[1])
    original_role = payload.get("role", "user")
    payload["role"] = "admin"           # Attempt privilege escalation
    payload["username"] = "hacker"

    tampered_payload_b64 = encode_b64(payload)
    # Keep original signature — it won't match anymore
    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

    # Try to verify the tampered token
    try:
        jwt.decode(
            tampered_token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_aud": False, "verify_iss": False}
        )
        verification_result = "VERIFICATION PASSED (this should not happen!)"
        success = True
    except JWTError as e:
        verification_result = f"VERIFICATION FAILED: {str(e)}"
        success = False

    return {
        "original_token": original_token,
        "original_role": original_role,
        "tampered_payload": payload,
        "tampered_token": tampered_token,
        "verification_result": verification_result,
        "attack_succeeded": success,
        "lesson": (
            "The signature protects the payload from tampering. "
            "Without the server's secret key, you cannot forge a valid signature. "
            "This is why JWT signature verification is non-negotiable."
        ),
    }
