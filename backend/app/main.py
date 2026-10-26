"""
AIAC Cyber — Full-Stack Cybersecurity Incident Response Platform
FastAPI Application Entrypoint v3.0
"""
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.database import engine, Base, SessionLocal
from app.db.seed import seed_database, ensure_playbooks
from app.routers import (
    auth,
    incidents,
    ai,
    playbooks,
    analytics,
    audit,
    users,
    api_keys,
    integrations,
    notifications,
    health,
    websocket,
)
from app.routers.chatbot import router as chatbot_router
from app.routers.alert_generator import router as alert_gen_router
from app.routers.email_notifications import router as email_router
from app.services import auto_alert_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler initializing DB tables and seed data on startup."""
    logger.info("Initializing database schemas...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        ensure_playbooks(db)
        if settings.DEMO_MODE:
            logger.info("DEMO_MODE enabled — checking database seed state...")
            seed_database(db)
            logger.info("Database seed initialized successfully.")
    except Exception as e:
        logger.error(f"Error seeding database / playbooks: {e}")
    finally:
        db.close()


    if settings.is_production and settings.jwt_secret_is_default:
        logger.critical(
            "SECURITY WARNING: JWT_SECRET_KEY is the default placeholder. "
            "Set a strong secret in .env before deploying to production!"
        )

    # Start automated random-alert scheduler (every AUTO_ALERT_INTERVAL_SECONDS)
    if settings.AUTO_ALERT_ENABLED:
        logger.info(
            f"[AUTO-SCHEDULER] Enabled — firing every {settings.AUTO_ALERT_INTERVAL_SECONDS}s "
            f"→ {settings.NOTIFICATION_RECIPIENTS}"
        )
        auto_alert_scheduler.start_scheduler()
    else:
        logger.info("[AUTO-SCHEDULER] Disabled (AUTO_ALERT_ENABLED=false).")

    yield

    # Graceful shutdown
    auto_alert_scheduler.stop_scheduler()
    logger.info("Shutting down AIAC Cyber platform...")


app = FastAPI(
    title="AIAC Cyber Incident Response Platform",
    description=(
        "Production Full-Stack AI-Assisted Cybersecurity Incident Response Platform. "
        "Provides real-time SOC feeds, AI triage reasoning, AI Threat Assistant chatbot, "
        "containment playbook simulations, threat analytics, RBAC access control, "
        "automated email notifications, and tamper-evident audit logs."
    ),
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Only add HSTS in production
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Mount existing routers
app.include_router(health.router)
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)
app.include_router(ai.router, prefix=settings.API_V1_STR)
app.include_router(playbooks.router, prefix=settings.API_V1_STR)
app.include_router(analytics.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)
app.include_router(api_keys.router, prefix=settings.API_V1_STR)
app.include_router(integrations.router, prefix=settings.API_V1_STR)
app.include_router(notifications.router, prefix=settings.API_V1_STR)
app.include_router(websocket.router, prefix=settings.API_V1_STR)

# Mount new routers
app.include_router(chatbot_router, prefix=settings.API_V1_STR)
app.include_router(alert_gen_router, prefix=settings.API_V1_STR)
app.include_router(email_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_STR,
        "demo_mode": settings.DEMO_MODE,
        "ai_provider": settings.AI_PROVIDER,
    }
