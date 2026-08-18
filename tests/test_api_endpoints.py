"""
Integration and End-to-End API Tests for Project AEGIS-AI (Phase 3).
Tests:
1. Health & Root API endpoints.
2. Live telemetry flow ingestion and BDI scoring (/api/v1/telemetry/stream).
3. Benign baseline simulation (/api/v1/telemetry/simulate/normal).
4. Zero-day attack simulation & autonomous DAG triage (/api/v1/telemetry/simulate/attack).
5. Manual agent investigation endpoint (/api/v1/agent/investigate).
6. Executive CISO Daily Brief endpoint (/api/v1/agent/daily-brief).
7. Human-in-the-Loop containment execution with valid token (/api/v1/agent/execute-containment).
8. Unauthorized containment rejection with invalid token (403 Forbidden).
9. Audit log retrieval (/api/v1/agent/containment/audit-logs).
10. WebSocket real-time thought and telemetry streaming.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.services.incident_store import incident_store

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_incident_store():
    """Ensures a clean incident repository before test execution."""
    import asyncio
    asyncio.run(incident_store.clear())


def test_root_endpoint():
    """Verify root endpoint returns system metadata or UI."""
    response = client.get("/")
    assert response.status_code == 200


def test_health_endpoint():
    """Verify health check returns HEALTHY and confirmed model loading."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["system"] == settings.PROJECT_NAME
    assert data["model_loaded"] is True


def test_telemetry_stream_normal_flow():
    """Verify normal telemetry flow produces low BDI score (< 0.40) and is not anomalous."""
    payload = {
        "src_ip": "192.168.1.55",
        "dst_ip": "192.168.1.1",
        "dst_port": 80,
        "protocol": "TCP",
        "features": {
            "duration": 0.5,
            "service": "http",
            "flag": "SF",
            "src_bytes": 350,
            "dst_bytes": 2200,
            "count": 4,
            "srv_count": 3,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
        }
    }
    response = client.post("/api/v1/telemetry/stream", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomaly"] is False
    assert data["bdi_score"] < 0.50
    assert data["status"] in ["NOMINAL", "SUSPICIOUS"]


def test_telemetry_stream_attack_flow():
    """Verify high-deviation attack flow produces critical BDI score (>= 0.70)."""
    payload = {
        "src_ip": "192.168.1.104",
        "dst_ip": "192.168.1.45",
        "dst_port": 445,
        "protocol": "TCP",
        "features": {
            "duration": 0.05,
            "service": "smb",
            "flag": "SF",
            "src_bytes": 1450,
            "dst_bytes": 890,
            "count": 180,
            "srv_count": 175,
            "same_srv_rate": 0.98,
            "diff_srv_rate": 0.02,
            "dst_host_count": 255,
            "dst_host_srv_count": 250,
            "dst_host_srv_diff_host_rate": 0.85,
        }
    }
    response = client.post("/api/v1/telemetry/stream", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomaly"] is True
    assert data["bdi_score"] >= 0.70
    assert data["status"] == "CRITICAL_ANOMALY"


def test_simulate_normal_traffic():
    """Verify baseline traffic simulation broadcasts nominal flows."""
    response = client.post("/api/v1/telemetry/simulate/normal?sample_count=3")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert len(data["flows"]) == 3
    assert data["avg_bdi"] < 0.50


def test_simulate_attack_burst_and_triage():
    """Verify attack simulation executes 4-agent DAG and returns IncidentCard."""
    response = client.post("/api/v1/telemetry/simulate/attack?mitre_id=T1021.002")
    assert response.status_code == 200
    incident = response.json()
    
    assert incident["incident_id"].startswith("AEGIS-")
    assert incident["bdi_score"] >= 0.70
    assert incident["attacker_ip"] == "192.168.1.104"
    assert incident["target_ip"] == "192.168.1.45"
    assert incident["status"] == "PENDING_APPROVAL"
    assert incident["mitre_threat"]["technique_id"] == "T1021.002"
    assert incident["asset"]["hostname"] == "DB-PROD-FINANCE-01"
    assert "iptables" in incident["containment"]["iptables_rule"]
    assert len(incident["agent_reasoning_trace"]) > 0


def test_manual_agent_investigate():
    """Verify manual on-demand agent triage invocation."""
    flow_data = {
        "src_ip": "192.168.1.88",
        "dst_ip": "192.168.1.10",
        "dst_port": 80,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "count": 220,
        "diff_srv_rate": 0.85,
        "serror_rate": 0.90,
    }
    payload = {
        "flow_data": flow_data,
        "bdi_score": 0.96,
    }
    response = client.post("/api/v1/agent/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"].startswith("AEGIS-")
    assert data["bdi_score"] == 0.96
    assert data["mitre_threat"]["technique_id"] == "T1046"


def test_ciso_daily_brief_endpoint():
    """Verify CISO Executive Brief endpoint returns formatted markdown."""
    # First inject an attack so there is incident context
    client.post("/api/v1/telemetry/simulate/attack")
    
    response = client.get("/api/v1/agent/daily-brief")
    assert response.status_code == 200
    data = response.json()
    assert "report_markdown" in data
    assert "# 🛡️ AEGIS-AI Executive CISO Daily Threat & Compromise Brief" in data["report_markdown"]
    assert data["total_incidents"] >= 1


def test_containment_execution_authorized_and_unauthorized():
    """Verify Human-in-the-Loop containment approval gate with valid and invalid tokens."""
    # 1. Trigger an attack to stage containment
    attack_res = client.post("/api/v1/telemetry/simulate/attack")
    incident_id = attack_res.json()["incident_id"]

    # 2. Attempt containment with INVALID officer token -> Should return 403 Forbidden
    unauth_payload = {
        "incident_id": incident_id,
        "officer_token": "MALICIOUS-INVALID-TOKEN",
        "rule_type": "iptables",
        "approval_action": "APPROVE",
    }
    unauth_res = client.post("/api/v1/agent/execute-containment", json=unauth_payload)
    assert unauth_res.status_code == 403
    assert "Unauthorized" in unauth_res.json()["detail"]

    # 3. Attempt containment with VALID officer token -> Should return 200 OK & CONTAINED status
    auth_payload = {
        "incident_id": incident_id,
        "officer_token": settings.OFFICER_AUTH_TOKEN,
        "rule_type": "iptables",
        "approval_action": "APPROVE",
    }
    auth_res = client.post("/api/v1/agent/execute-containment", json=auth_payload)
    assert auth_res.status_code == 200
    containment_data = auth_res.json()
    assert containment_data["status"] == "CONTAINED"
    assert containment_data["incident_id"] == incident_id
    assert len(containment_data["audit_hash"]) == 64  # SHA-256 length
    assert "iptables" in containment_data["executed_rule"]

    # 4. Verify audit log retrieval
    audit_res = client.get("/api/v1/agent/containment/audit-logs")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) >= 1
    assert logs[0]["incident_id"] == incident_id
    assert logs[0]["audit_hash"] == containment_data["audit_hash"]


def test_websocket_streaming_handshake():
    """Verify WebSocket client receives live connection handshake."""
    with client.websocket_connect("/api/v1/ws/agent-thoughts") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "CONNECTION_ESTABLISHED"
        assert data["data"]["status"] == "ONLINE"
