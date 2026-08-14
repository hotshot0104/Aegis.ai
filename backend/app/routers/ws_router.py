"""
WebSocket Streaming Router for Project AEGIS-AI.
Endpoint:
- WebSocket /api/v1/ws/agent-thoughts: Streams sub-second agent reasoning steps,
  telemetry ticks, and containment state changes to the SOC dashboard.
"""

import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.websocket_manager import ws_manager

logger = logging.getLogger("aegis.ws_router")
router = APIRouter(prefix="/ws", tags=["Real-Time WebSocket Streaming"])


@router.websocket("/agent-thoughts")
async def websocket_agent_thoughts_endpoint(websocket: WebSocket) -> None:
    """Sub-second streaming WebSocket connection for real-time agent thoughts,
    live anomaly meter telemetry ticks, and interactive containment updates.
    """
    await ws_manager.connect(websocket)

    # Send initial welcome handshake
    await websocket.send_json({
        "type": "CONNECTION_ESTABLISHED",
        "data": {
            "message": "Connected to AEGIS-AI Real-Time SOC Stream.",
            "status": "ONLINE",
            "channels": ["AGENT_THOUGHT", "TELEMETRY_TICK", "INCIDENT_CREATED", "CONTAINMENT_UPDATE"],
        }
    })

    try:
        while True:
            # Keep connection open and receive optional ping/control frames from dashboard
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket connection error: {exc}")
        await ws_manager.disconnect(websocket)
