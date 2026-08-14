"""
Core Package for Project AEGIS-AI.
Exports configuration settings and security authentication utilities.
"""

from backend.app.core.config import Settings, settings
from backend.app.core.security import verify_officer_token, generate_audit_hash

__all__ = [
    "Settings",
    "settings",
    "verify_officer_token",
    "generate_audit_hash",
]
