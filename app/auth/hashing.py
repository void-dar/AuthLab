"""
Password Hashing Module
=======================
Implements both Argon2id and bcrypt for educational comparison.

WHY HASH PASSWORDS?
If your database leaks, hashed passwords can't be reversed.
But not all hashes are equal:

  MD5/SHA1/SHA256 → NEVER use for passwords. Fast = bad here.
  bcrypt          → Good. Slow by design. Memory-light.
  scrypt          → Better. Memory-hard.
  Argon2id        → Best. Memory-hard + GPU-resistant. PHC winner 2015.

The key insight: slowness and memory cost are FEATURES, not bugs.
They make brute-force attacks computationally expensive.
"""
from passlib.context import CryptContext
from passlib.hash import argon2 as passlib_argon2
import bcrypt as bcrypt_lib
import hashlib
import time
from typing import NamedTuple

# Primary context — Argon2id is the default (PHC winner)
argon2_context = CryptContext(schemes=["argon2"], deprecated="auto")

# bcrypt context for comparison
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Used for all production storage."""
    return argon2_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its Argon2id hash. Constant-time."""
    try:
        return argon2_context.verify(plain, hashed)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# EDUCATIONAL HASHING DEMO FUNCTIONS
# ─────────────────────────────────────────────────────────────

class HashDemo(NamedTuple):
    algorithm: str
    hash_value: str
    time_ms: float
    parameters: dict
    explanation: str
    security_level: str     # weak | moderate | strong | very_strong


def demo_hash_password(password: str) -> dict:
    """
    Generate hashes with multiple algorithms for educational comparison.
    Returns timing, parameters, and security analysis for each.
    """
    results = {}

    # ── 1. MD5 (NEVER use for passwords — shown as what NOT to do)
    t0 = time.perf_counter()
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    t1 = time.perf_counter()
    results["md5"] = HashDemo(
        algorithm="MD5",
        hash_value=md5_hash,
        time_ms=round((t1 - t0) * 1000, 4),
        parameters={"output_bits": 128},
        explanation="Cryptographic hash, NOT designed for passwords. No salt, no cost factor. Billions of hashes/second possible on GPU.",
        security_level="very_weak"
    )

    # ── 2. SHA-256 (better than MD5, still wrong for passwords)
    t0 = time.perf_counter()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    t1 = time.perf_counter()
    results["sha256"] = HashDemo(
        algorithm="SHA-256",
        hash_value=sha256_hash,
        time_ms=round((t1 - t0) * 1000, 4),
        parameters={"output_bits": 256},
        explanation="Secure general-purpose hash. Still wrong for passwords — no salt by default, too fast. Hundreds of millions of hashes/sec on GPU.",
        security_level="weak"
    )

    # ── 3. SHA-256 with manual salt (slightly better, still wrong)
    import secrets as sec
    manual_salt = sec.token_hex(16)
    t0 = time.perf_counter()
    salted_sha = hashlib.sha256((manual_salt + password).encode()).hexdigest()
    t1 = time.perf_counter()
    results["sha256_salted"] = HashDemo(
        algorithm="SHA-256 + Salt",
        hash_value=f"$salt${manual_salt}${salted_sha}",
        time_ms=round((t1 - t0) * 1000, 4),
        parameters={"salt_bytes": 16, "output_bits": 256},
        explanation="Salting prevents rainbow table attacks. But SHA-256 is still too fast — attackers can try billions of passwords/sec.",
        security_level="weak"
    )

    # ── 4. bcrypt
    try:
        import bcrypt as bcrypt_lib
        t0 = time.perf_counter()
        bc_salt = bcrypt_lib.gensalt(rounds=12)
        bcrypt_hash = bcrypt_lib.hashpw(password.encode(), bc_salt).decode()
        t1 = time.perf_counter()
    except Exception:
        t0 = t1 = time.perf_counter()
        bcrypt_hash = "$2b$12$[bcrypt would appear here]"
    results["bcrypt"] = HashDemo(
        algorithm="bcrypt (rounds=12)",
        hash_value=bcrypt_hash,
        time_ms=round((t1 - t0) * 1000, 2),
        parameters={
            "rounds": 12,
            "salt_bits": 128,
            "output_bits": 184,
            "memory_kb": 4
        },
        explanation="bcrypt is deliberately slow. Built-in salt. Cost factor configurable. ~100ms per hash makes brute-force ~10,000x harder than SHA-256. Weakness: memory-light, so GPU attacks still feasible.",
        security_level="strong"
    )

    # ── 5. Argon2id (the gold standard)
    t0 = time.perf_counter()
    argon2_hash = argon2_context.hash(password)
    t1 = time.perf_counter()
    results["argon2id"] = HashDemo(
        algorithm="Argon2id (t=2, m=65536, p=2)",
        hash_value=argon2_hash,
        time_ms=round((t1 - t0) * 1000, 2),
        parameters={
            "time_cost": 2,
            "memory_cost_kb": 65536,
            "parallelism": 2,
            "salt_bits": 128,
            "output_bits": 256,
            "variant": "id (hybrid of Argon2i + Argon2d)"
        },
        explanation="PHC winner 2015. Memory-hard: requires 64MB RAM per hash attempt. This kills GPU/ASIC attacks — GPUs have limited per-core RAM. Variant 'id' resists both side-channel and time-memory trade-off attacks.",
        security_level="very_strong"
    )

    return {k: v._asdict() for k, v in results.items()}


def analyze_password_strength(password: str) -> dict:
    """
    Educational password strength analysis.
    Returns score, issues, and suggestions.
    """
    issues = []
    score = 0

    if len(password) >= 8:
        score += 20
    else:
        issues.append("Too short (minimum 8 characters)")

    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10

    if any(c.isupper() for c in password):
        score += 15
    else:
        issues.append("Add uppercase letters (A-Z)")

    if any(c.islower() for c in password):
        score += 15
    else:
        issues.append("Add lowercase letters (a-z)")

    if any(c.isdigit() for c in password):
        score += 15
    else:
        issues.append("Add numbers (0-9)")

    special = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
    if any(c in special for c in password):
        score += 15
    else:
        issues.append("Add special characters (!@#$%^&*)")

    # Common password check (mini list for demo)
    common = ["password", "123456", "qwerty", "letmein", "admin", "welcome"]
    if password.lower() in common:
        score = max(0, score - 40)
        issues.append("This is a commonly used password")

    if score >= 80:
        level = "Very Strong"
        color = "#22c55e"
    elif score >= 60:
        level = "Strong"
        color = "#84cc16"
    elif score >= 40:
        level = "Moderate"
        color = "#eab308"
    elif score >= 20:
        level = "Weak"
        color = "#f97316"
    else:
        level = "Very Weak"
        color = "#ef4444"

    # Entropy estimate
    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(c in special for c in password): charset_size += 32

    import math
    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

    return {
        "score": score,
        "level": level,
        "color": color,
        "issues": issues,
        "entropy_bits": round(entropy, 1),
        "charset_size": charset_size,
        "length": len(password),
    }
