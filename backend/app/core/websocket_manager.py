"""
WebSocket Connection Manager for Project AEGIS-AI.
Broadcasting hub for real-time telemetry metrics, BDI anomaly ticks,
sub-second agent reasoning thought events, and containment status updates.
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from fastapi import WebSocket

from backend.app.models.incident import AgentThoughtEvent

logger = logging.getLogger("aegis.websocket")


class WebSocketManager:
    """Manages active WebSocket client connections and broadcasts live SOC events."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts and registers a new client WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Unregisters a disconnected WebSocket client."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Remaining clients: {len(self.active_connections)}")

    async def broadcast_json(self, message: Dict[str, Any]) -> None:
        """Broadcasts a JSON dictionary payload to all active WebSocket clients."""
        if not self.active_connections:
            return

        dead_connections = []
        async with self._lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.warning(f"Error broadcasting to WebSocket client: {exc}")
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    if dead in self.active_connections:
                        self.active_connections.remove(dead)

    async def broadcast_thought(self, event: AgentThoughtEvent) -> None:
        """Helper to serialize and broadcast a real-time agent thought event."""
        payload = {
            "type": "AGENT_THOUGHT",
            "data": {
                "agent_name": event.agent_name,
                "step_type": event.step_type,
                "message": event.message,
                "timestamp": event.timestamp.isoformat(),
                "metadata": event.metadata,
            }
        }
        await self.broadcast_json(payload)

    async def broadcast_telemetry(self, telemetry_data: Dict[str, Any]) -> None:
        """Helper to broadcast live telemetry tick and BDI scoring to the Anomaly Meter gauge."""
        payload = {
            "type": "TELEMETRY_TICK",
            "data": telemetry_data,
        }
        await self.broadcast_json(payload)

    async def broadcast_containment(self, containment_data: Dict[str, Any]) -> None:
        """Helper to broadcast containment approval confirmation and status changes."""
        payload = {
            "type": "CONTAINMENT_UPDATE",
            "data": containment_data,
        }
        await self.broadcast_json(payload)


# Global WebSocketManager instance
ws_manager = WebSocketManager()
