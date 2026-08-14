"""
Routers package for Project AEGIS-AI FastAPI endpoints.
Exports telemetry_router, agent_router, containment_router, and ws_router.
"""

from backend.app.routers.telemetry_router import router as telemetry_router
from backend.app.routers.agent_router import router as agent_router
from backend.app.routers.containment_router import router as containment_router
from backend.app.routers.ws_router import router as ws_router

__all__ = [
    "telemetry_router",
    "agent_router",
    "containment_router",
    "ws_router",
]
