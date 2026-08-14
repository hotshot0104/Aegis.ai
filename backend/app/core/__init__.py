"""
Core Package for Project AEGIS-AI.
Exports configuration settings, security utilities, and WebSocket broadcasting manager.
"""

from backend.app.core.config import Settings, settings
from backend.app.core.security import verify_officer_token, generate_audit_hash
from backend.app.core.websocket_manager import WebSocketManager, ws_manager

__all__ = [
    "Settings",
    "settings",
    "verify_officer_token",
    "generate_audit_hash",
    "WebSocketManager",
    "ws_manager",
]
