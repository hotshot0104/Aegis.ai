"""
Unit Tests for Project AEGIS-AI Core Security & Cryptography Module.
Verifies:
1. Constant-time officer authentication token matching (Rule 3 HITL Gate).
2. Rejection of invalid, empty, or malicious token attempts.
3. Cryptographic SHA-256 tamper-evident audit hashing.
"""

from backend.app.core.security import verify_officer_token, generate_audit_hash, DEFAULT_DEMO_OFFICER_TOKEN


def test_verify_officer_token_valid():
    """Verify correct officer token is accepted."""
    assert verify_officer_token(DEFAULT_DEMO_OFFICER_TOKEN) is True
    assert verify_officer_token("SOC-OFFICER-AUTH-TOKEN-DEMO", "SOC-OFFICER-AUTH-TOKEN-DEMO") is True


def test_verify_officer_token_invalid():
    """Verify invalid or forged tokens are rejected."""
    assert verify_officer_token("FORGED-ATTACKER-TOKEN") is False
    assert verify_officer_token("") is False
    assert verify_officer_token(None) is False
    assert verify_officer_token("SOC-OFFICER-AUTH-TOKEN-DEMO-EXTRA") is False


def test_generate_audit_hash_deterministic():
    """Verify SHA-256 audit digest is deterministic and tamper-evident."""
    event_1 = {
        "incident_id": "AEGIS-123456",
        "action": "CONTAIN_SOURCE_IP",
        "officer": "analyst-01",
        "target_ip": "192.168.1.104",
    }
    event_2 = dict(event_1)
    
    hash_1 = generate_audit_hash(event_1)
    hash_2 = generate_audit_hash(event_2)
    
    assert isinstance(hash_1, str)
    assert len(hash_1) == 64  # SHA-256 hex length
    assert hash_1 == hash_2  # Deterministic

    # Tampered event produces completely different hash
    tampered = dict(event_1)
    tampered["target_ip"] = "192.168.1.105"
    assert generate_audit_hash(tampered) != hash_1
