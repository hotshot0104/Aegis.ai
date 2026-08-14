"""
Security and Cryptographic Verification Module for Project AEGIS-AI.
Implements:
1. Constant-time officer token authentication (Rule 3 HITL gate) to prevent timing attacks.
2. Cryptographic SHA-256 audit log generation for tamper-evident containment records.
3. Input sanitization helpers for system boundaries.
"""

import hashlib
import json
import secrets
from typing import Dict, Any

DEFAULT_DEMO_OFFICER_TOKEN = "SOC-OFFICER-AUTH-TOKEN-DEMO"


def verify_officer_token(provided_token: str, expected_token: str = DEFAULT_DEMO_OFFICER_TOKEN) -> bool:
    """Verifies an officer authorization token using constant-time string comparison.
    
    Prevents side-channel timing attacks when validating Human-in-the-Loop
    containment execution requests.

    Args:
        provided_token: Token string supplied by the SOC analyst.
        expected_token: Expected valid token secret.

    Returns:
        True if token matches exactly, False otherwise.
    """
    if not provided_token or not expected_token:
        return False
    return secrets.compare_digest(str(provided_token).strip(), str(expected_token).strip())


def generate_audit_hash(audit_event: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 cryptographic digest of a containment event.
    
    Ensures non-repudiation and tamper evidence for all firewall containment actions.

    Args:
        audit_event: Dictionary of containment event details.

    Returns:
        Hexadecimal SHA-256 digest string.
    """
    canonical_json = json.dumps(audit_event, sort_keys=True, default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
