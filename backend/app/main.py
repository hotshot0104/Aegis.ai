"""
Main FastAPI Application Entrypoint for Project AEGIS-AI.
Configures:
- Async lifespan startup (ML model pre-loading)
- CORS Middleware
- API v1 Routers (Telemetry, Multi-Agent Core, HITL Containment, WebSockets)
- Healthcheck & Static File Serving for the SOC Dashboard
"""

import os
from contextlib import asynccontextmanager
from typing import Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import asyncio
from backend.app.core.config import settings
from backend.app.routers.telemetry_router import router as telemetry_router, get_detector, continuous_telemetry_loop
from backend.app.routers.agent_router import router as agent_router
from backend.app.routers.containment_router import router as containment_router
from backend.app.routers.ws_router import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to handle application startup and shutdown events."""
    # Startup: Pre-load the Isolation Forest ML perception model into memory
    print(f"[*] Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
    detector = get_detector()
    if detector.is_trained:
        print(f"[+] Anomaly Detector pre-loaded successfully from {settings.MODEL_PATH}")
    else:
        print(f"[!] Warning: Anomaly Detector model not found or untrained at {settings.MODEL_PATH}")

    # Start background telemetry generator loop
    telemetry_task = asyncio.create_task(continuous_telemetry_loop())

    yield

    # Shutdown: Clean up any active connections
    print(f"[*] Shutting down {settings.PROJECT_NAME}...")
    telemetry_task.cancel()



app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
app.include_router(telemetry_router, prefix=settings.API_V1_STR)
app.include_router(agent_router, prefix=settings.API_V1_STR)
app.include_router(containment_router, prefix=settings.API_V1_STR)
app.include_router(ws_router, prefix=settings.API_V1_STR)

# Mount frontend directory for static UI serving if it exists
PROJECT_ROOT = os.path.dirname(settings.BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
if not os.path.exists(FRONTEND_DIR):
    FRONTEND_DIR = os.path.join(settings.BASE_DIR, "frontend")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint. Serves the SOC Dashboard if available, else returns API metadata."""
    index_html = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_html):
        return FileResponse(index_html)
    return {
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "description": settings.DESCRIPTION,
        "docs_url": "/docs",
        "api_v1_prefix": settings.API_V1_STR,
    }


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for container orchestrators and SRE monitoring."""
    detector = get_detector()
    return {
        "status": "HEALTHY",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_loaded": detector.is_trained,
        "model_path": settings.MODEL_PATH,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
