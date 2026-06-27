"""
AuthLab — Main Application
===========================
FastAPI application entry point.
Registers all routers, middleware, templates, and static files.
Initializes the database on startup.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database.db import init_db
from app.routers.auth_router import router as auth_router
from app.routers.demo_router import router as demo_router
from app.routers.admin_router import router as admin_router

settings = get_settings()

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("authlab")


# ─────────────────────────────────────────────────────────────
# LIFESPAN (startup/shutdown)
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 AuthLab starting up...")
    init_db()
    logger.info("✅ Database ready")
    yield
    logger.info("🛑 AuthLab shutting down")


# ─────────────────────────────────────────────────────────────
# APP INSTANCE
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ─────────────────────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# STATIC FILES & TEMPLATES
# ─────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ─────────────────────────────────────────────────────────────
# ROUTERS
# ─────────────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(demo_router)
app.include_router(admin_router)


# ─────────────────────────────────────────────────────────────
# PAGE ROUTES (Jinja2 templates)
# ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("pages/home.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("auth/register.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("pages/dashboard.html", {"request": request})


@app.get("/demo/hashing", response_class=HTMLResponse)
async def hashing_demo_page(request: Request):
    return templates.TemplateResponse("demo/hashing.html", {"request": request})


@app.get("/demo/jwt", response_class=HTMLResponse)
async def jwt_demo_page(request: Request):
    return templates.TemplateResponse("demo/jwt.html", {"request": request})


@app.get("/demo/sessions", response_class=HTMLResponse)
async def sessions_demo_page(request: Request):
    return templates.TemplateResponse("demo/sessions.html", {"request": request})


@app.get("/demo/mfa", response_class=HTMLResponse)
async def mfa_demo_page(request: Request):
    return templates.TemplateResponse("demo/mfa.html", {"request": request})


@app.get("/demo/rbac", response_class=HTMLResponse)
async def rbac_demo_page(request: Request):
    return templates.TemplateResponse("demo/rbac.html", {"request": request})


@app.get("/demo/abac", response_class=HTMLResponse)
async def abac_demo_page(request: Request):
    return templates.TemplateResponse("demo/abac.html", {"request": request})


@app.get("/demo/oauth", response_class=HTMLResponse)
async def oauth_demo_page(request: Request):
    return templates.TemplateResponse("demo/oauth.html", {"request": request})


@app.get("/demo/sso", response_class=HTMLResponse)
async def sso_demo_page(request: Request):
    return templates.TemplateResponse("demo/sso.html", {"request": request})


@app.get("/demo/attacks", response_class=HTMLResponse)
async def attacks_demo_page(request: Request):
    return templates.TemplateResponse("demo/attacks.html", {"request": request})


@app.get("/demo/passwordless", response_class=HTMLResponse)
async def passwordless_demo_page(request: Request):
    return templates.TemplateResponse("demo/passwordless.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin/dashboard.html", {"request": request})


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request):
    return templates.TemplateResponse("admin/users.html", {"request": request})


@app.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs_page(request: Request):
    return templates.TemplateResponse("admin/logs.html", {"request": request})


@app.get("/admin/tokens", response_class=HTMLResponse)
async def admin_tokens_page(request: Request):
    return templates.TemplateResponse("admin/tokens.html", {"request": request})
