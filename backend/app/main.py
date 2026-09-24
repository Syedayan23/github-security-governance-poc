"""
FastAPI Main Application for GitHub Security Alert Governance POC.

Initializes application, database, CORS, and registers API endpoints:
- GET /health
- GET /alerts
- GET /alerts/{id}
- GET /alerts/summary
- POST /sync
- POST /webhooks/github
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings
from backend.app.database import init_db, get_connection
from backend.app.models import HealthResponse
from backend.app.routes.alerts import router as alerts_router
from backend.app.routes.webhooks import router as webhooks_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes SQLite database tables on application startup."""
    init_db()
    yield


app = FastAPI(
    title="GitHub Security Alert Governance POC API",
    description="Unified governance and tracking for GitHub Dependabot and CodeQL Code Scanning alerts.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local React development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """Returns application health and configuration readiness."""
    db_connected = False
    try:
        conn = get_connection()
        conn.execute("SELECT 1;")
        conn.close()
        db_connected = True
    except Exception:
        db_connected = False

    return HealthResponse(
        status="healthy" if db_connected else "degraded",
        repository_configured=settings.repository_full_name,
        database_connected=db_connected,
        github_token_configured=bool(settings.github_token),
        webhook_secret_configured=bool(settings.github_webhook_secret)
    )


# Register routes
app.include_router(alerts_router)
app.include_router(webhooks_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.host, port=settings.port, reload=True)
