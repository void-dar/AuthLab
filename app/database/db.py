"""
Database Setup & Initialization
================================
Creates the SQLite database, all tables, and seeds essential data.

SQLModel uses SQLAlchemy under the hood — we create tables via
SQLModel.metadata.create_all() which reads our model definitions.
"""
import json
import secrets
from datetime import datetime, timedelta, timezone
from sqlmodel import SQLModel, Session, create_engine, select
from app.config import get_settings
from app.models.models import (
    Role, Permission, RolePermission, User, OAuthClient,
    Post, AuditLog
)

settings = get_settings()

# SQLite engine with WAL mode for better concurrency
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={
        "check_same_thread": False,
        "timeout": 30,
    }
)


def get_session():
    """FastAPI dependency: yields a database session."""
    with Session(engine) as session:
        yield session


def init_db():
    """Create all tables and seed initial data."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        _seed_roles(session)
        _seed_permissions(session)
        _seed_role_permissions(session)
        _seed_users(session)
        _seed_oauth_clients(session)
        _seed_posts(session)
        session.commit()
    print("✅ Database initialized with seed data")


# ─────────────────────────────────────────────────────────────
# SEED DATA
# ─────────────────────────────────────────────────────────────

ROLES = [
    {"name": "admin",     "description": "Full system access",                      "level": 100},
    {"name": "moderator", "description": "Content moderation, user management",     "level": 60},
    {"name": "staff",     "description": "Internal staff with elevated read access","level": 40},
    {"name": "user",      "description": "Standard registered user",                "level": 20},
    {"name": "guest",     "description": "Unauthenticated or unverified visitor",   "level": 0},
]

PERMISSIONS = [
    # Users
    {"name": "users:read",   "resource": "users",   "action": "read",   "description": "View user list"},
    {"name": "users:create", "resource": "users",   "action": "create", "description": "Create new users"},
    {"name": "users:update", "resource": "users",   "action": "update", "description": "Update any user"},
    {"name": "users:delete", "resource": "users",   "action": "delete", "description": "Delete users"},
    {"name": "users:ban",    "resource": "users",   "action": "ban",    "description": "Ban/lock user accounts"},
    # Posts
    {"name": "posts:read",   "resource": "posts",   "action": "read",   "description": "View posts"},
    {"name": "posts:create", "resource": "posts",   "action": "create", "description": "Create posts"},
    {"name": "posts:update", "resource": "posts",   "action": "update", "description": "Edit any post"},
    {"name": "posts:delete", "resource": "posts",   "action": "delete", "description": "Delete any post"},
    # Admin
    {"name": "admin:dashboard", "resource": "admin", "action": "view",  "description": "Access admin dashboard"},
    {"name": "admin:logs",      "resource": "admin", "action": "logs",  "description": "View audit logs"},
    {"name": "admin:tokens",    "resource": "admin", "action": "tokens","description": "View/revoke tokens"},
    # Reports
    {"name": "reports:read",    "resource": "reports","action": "read", "description": "View security reports"},
]

# Which permissions each role gets
ROLE_PERMISSIONS = {
    "admin":     [p["name"] for p in PERMISSIONS],       # All permissions
    "moderator": ["users:read", "users:ban", "posts:read", "posts:update", "posts:delete", "reports:read"],
    "staff":     ["users:read", "posts:read", "posts:create", "posts:update"],
    "user":      ["posts:read", "posts:create"],
    "guest":     ["posts:read"],
}

DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@authlab.edu",
        "full_name": "Admin User",
        "role": "admin",
        "department": "engineering",
        "clearance_level": 5,
        "age": 30,
        "country": "US",
        "membership_status": "enterprise",
    },
    {
        "username": "moderator",
        "email": "mod@authlab.edu",
        "full_name": "Mod User",
        "role": "moderator",
        "department": "operations",
        "clearance_level": 3,
        "age": 28,
        "country": "GB",
        "membership_status": "premium",
    },
    {
        "username": "staff1",
        "email": "staff@authlab.edu",
        "full_name": "Staff Member",
        "role": "staff",
        "department": "finance",
        "clearance_level": 2,
        "age": 25,
        "country": "NG",
        "membership_status": "premium",
    },
    {
        "username": "alice",
        "email": "alice@authlab.edu",
        "full_name": "Alice Johnson",
        "role": "user",
        "department": "marketing",
        "clearance_level": 1,
        "age": 22,
        "country": "NG",
        "membership_status": "free",
    },
    {
        "username": "bob",
        "email": "bob@authlab.edu",
        "full_name": "Bob Smith",
        "role": "user",
        "department": "hr",
        "clearance_level": 1,
        "age": 35,
        "country": "CA",
        "membership_status": "premium",
    },
]


def _seed_roles(session: Session):
    for role_data in ROLES:
        existing = session.exec(select(Role).where(Role.name == role_data["name"])).first()
        if not existing:
            session.add(Role(**role_data))
    session.flush()


def _seed_permissions(session: Session):
    for perm_data in PERMISSIONS:
        existing = session.exec(select(Permission).where(Permission.name == perm_data["name"])).first()
        if not existing:
            session.add(Permission(**perm_data))
    session.flush()


def _seed_role_permissions(session: Session):
    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = session.exec(select(Role).where(Role.name == role_name)).first()
        if not role:
            continue
        for perm_name in perm_names:
            perm = session.exec(select(Permission).where(Permission.name == perm_name)).first()
            if not perm:
                continue
            existing = session.exec(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == perm.id
                )
            ).first()
            if not existing:
                session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    session.flush()


def _seed_users(session: Session):
    # Import here to avoid circular import
    from app.auth.hashing import hash_password

    for user_data in DEMO_USERS:
        existing = session.exec(select(User).where(User.username == user_data["username"])).first()
        if existing:
            continue
        role = session.exec(select(Role).where(Role.name == user_data["role"])).first()
        user = User(
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"],
            password_hash=hash_password("Password123!"),   # Demo password
            role_id=role.id if role else 5,
            is_active=True,
            is_verified=True,
            department=user_data["department"],
            clearance_level=user_data["clearance_level"],
            age=user_data["age"],
            country=user_data["country"],
            membership_status=user_data["membership_status"],
        )
        session.add(user)
    session.flush()


def _seed_oauth_clients(session: Session):
    from app.auth.hashing import hash_password
    clients = [
        {
            "client_id": "inventory-app",
            "client_secret": "inventory-secret-abc123",
            "name": "Inventory System",
            "description": "Simulated inventory management application",
            "redirect_uri": "http://localhost:8000/demo/oauth/callback",
            "allowed_scopes": "openid profile email inventory:read",
        },
        {
            "client_id": "payroll-app",
            "client_secret": "payroll-secret-xyz789",
            "name": "Payroll System",
            "description": "Simulated payroll management application",
            "redirect_uri": "http://localhost:8000/demo/sso/payroll/callback",
            "allowed_scopes": "openid profile email payroll:read",
        },
    ]
    for c in clients:
        existing = session.exec(select(OAuthClient).where(OAuthClient.client_id == c["client_id"])).first()
        if not existing:
            session.add(OAuthClient(
                client_id=c["client_id"],
                client_secret_hash=hash_password(c["client_secret"]),
                name=c["name"],
                description=c["description"],
                redirect_uri=c["redirect_uri"],
                allowed_scopes=c["allowed_scopes"],
            ))
    session.flush()


def _seed_posts(session: Session):
    posts_data = [
        {"title": "Introduction to JWT", "content": "JSON Web Tokens are a compact, URL-safe means of representing claims...", "owner_username": "alice"},
        {"title": "Why Argon2 beats bcrypt", "content": "Argon2 won the Password Hashing Competition in 2015...", "owner_username": "bob"},
        {"title": "Zero Trust Architecture", "content": "Never trust, always verify. Zero Trust is a security model that...", "owner_username": "alice"},
        {"title": "Admin Security Bulletin", "content": "This is an admin-only security bulletin for internal review.", "owner_username": "admin"},
        {"title": "Moderator Guidelines", "content": "Content moderation policy and procedures for moderators.", "owner_username": "moderator"},
    ]
    for p in posts_data:
        owner = session.exec(select(User).where(User.username == p["owner_username"])).first()
        if not owner:
            continue
        existing = session.exec(select(Post).where(Post.title == p["title"])).first()
        if not existing:
            session.add(Post(
                title=p["title"],
                content=p["content"],
                owner_id=owner.id,
                is_public=True,
            ))
