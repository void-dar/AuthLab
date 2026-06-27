"""
AuthLab Configuration
Centralizes all environment-driven settings using Pydantic Settings.
Following 12-factor app principles — no hardcoded secrets.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    # App identity
    APP_NAME: str = "AuthLab"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Interactive Authentication & Authorization Educational Platform"
    DEBUG: bool = Field(default=True)
    SECRET_KEY: str = Field(default="authlab-super-secret-key-change-in-production-min-32-chars")

    # Database
    DATABASE_URL: str = Field(default="sqlite:///./authlab.db")

    # JWT configuration
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15       # Short-lived: security best practice
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ISSUER: str = "authlab.edu"
    JWT_AUDIENCE: str = "authlab-users"

    # Session configuration
    SESSION_COOKIE_NAME: str = "authlab_session"
    SESSION_MAX_AGE_SECONDS: int = 3600             # 1 hour

    # OTP / MFA
    OTP_EXPIRE_MINUTES: int = 5
    OTP_LENGTH: int = 6

    # Password reset
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    # Magic link (passwordless)
    MAGIC_LINK_EXPIRE_MINUTES: int = 15

    # Rate limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_GLOBAL: str = "100/minute"

    # Account lockout
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Password policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # OAuth simulation
    OAUTH_AUTH_CODE_EXPIRE_SECONDS: int = 600

    # Hashing
    BCRYPT_ROUNDS: int = 12
    ARGON2_TIME_COST: int = 2
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 2

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton — only reads env once."""
    return Settings()
