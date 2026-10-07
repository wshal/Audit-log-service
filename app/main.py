"""
FastAPI application entrypoint for Schwab Tamper-Evident Audit Log Service.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers.audit import router as audit_router
from app.storage.database import get_engine, get_session_factory, init_db

# Engine and session creation
engine = get_engine(settings.DATABASE_URL)
SessionLocal = get_session_factory(engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    init_db(engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production-grade, tamper-evident audit log microservice with cryptographic hash chaining, "
        "structured redaction, configurable retention policies, and compliance reporting."
    ),
    lifespan=lifespan,
)

# Enable CORS for frontend/dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(audit_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
