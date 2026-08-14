"""Edge case validation script for comprehensive backend testing."""

from backend.app.services.cyber_tools import CyberTools
from backend.ml_engine.anomaly_detector import NetworkAnomalyDetector
import pytest


# --- IP Validation Tests ---

def test_containment_valid_ipv4():
    r = CyberTools.tool_generate_containment_command("192.168.1.104", 445, "tcp")
    assert "192.168.1.104" in r.iptables_rule

def test_containment_rejects_injection():
    with pytest.raises(ValueError, match="Invalid IP"):
        CyberTools.tool_generate_containment_command("EVIL; rm -rf /", 445, "tcp")

def test_containment_accepts_ipv6():
    r = CyberTools.tool_generate_containment_command("::1", 443, "tcp")
    assert "::1" in r.iptables_rule

def test_containment_port_clamping():
    r = CyberTools.tool_generate_containment_command("10.0.0.1", 99999, "tcp")
    assert "--dport 65535" in r.iptables_rule

def test_containment_port_zero_clamped_to_one():
    r = CyberTools.tool_generate_containment_command("10.0.0.1", 0, "tcp")
    assert "--dport 1" in r.iptables_rule

def test_containment_protocol_sanitization():
    r = CyberTools.tool_generate_containment_command("10.0.0.1", 80, "evil_proto")
    assert "-p tcp" in r.iptables_rule

def test_containment_udp_protocol():
    r = CyberTools.tool_generate_containment_command("10.0.0.1", 53, "udp")
    assert "-p udp" in r.iptables_rule


# --- Asset Registry Edge Cases ---

def test_unknown_ip_fallback():
    r = CyberTools.tool_query_asset_registry("1.2.3.4")
    assert r.hostname == "NODE-1-2-3-4"
    assert r.criticality_level == "MEDIUM"
    assert r.crown_jewel is False

def test_known_ip_resolution():
    r = CyberTools.tool_query_asset_registry("192.168.1.45")
    assert r.hostname == "DB-PROD-FINANCE-01"
    assert r.crown_jewel is True


# --- MITRE Search Edge Cases ---

def test_mitre_empty_flow():
    r = CyberTools.tool_mitre_vector_search({})
    assert r.technique_id == "UNKNOWN"
    assert r.confidence < 10.0


# --- Model Edge Cases ---

def test_empty_flow_dict_scoring():
    det = NetworkAnomalyDetector()
    res = det.score_flow_dict({})
    assert 0.0 <= res["bdi_score"] <= 1.0
    assert res["status"] in ["NOMINAL", "SUSPICIOUS", "CRITICAL_ANOMALY"]

def test_model_untrained_raises():
    import tempfile, os
    tmp_path = os.path.join(tempfile.gettempdir(), "nonexistent_model.joblib")
    det = NetworkAnomalyDetector(model_path=tmp_path)
    det.is_trained = False
    det.model = None
    import numpy as np
    with pytest.raises(RuntimeError, match="not trained"):
        det.score_vector(np.zeros(41))
