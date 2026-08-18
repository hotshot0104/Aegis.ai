"""
Unit Tests for Phase 1: Unsupervised Perception & Anomaly Engine.
Tests:
1. Model loading & serialization.
2. Anomaly inference latency (< 5ms per vector).
3. BDI scoring on normal flow records (BDI <= 0.25, is_anomaly=False).
4. BDI scoring on zero-day attack flow records (BDI >= 0.80, is_anomaly=True).
5. RollingFalsePositiveFilter (suppression of transient spikes vs escalation on K=3).
"""

import os
import json
import time
import asyncio
import pytest
import numpy as np
import pandas as pd
from backend.ml_engine.anomaly_detector import NetworkAnomalyDetector
from backend.ml_engine.rolling_filter import RollingFalsePositiveFilter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "backend", "data")
MODELS_DIR = os.path.join(BASE_DIR, "backend", "models_saved")
MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_benign.joblib")


@pytest.fixture(scope="module")
def detector() -> NetworkAnomalyDetector:
    """Fixture to ensure a trained model is loaded."""
    if not os.path.exists(MODEL_PATH):
        from backend.ml_engine.train_model import train_and_evaluate
        train_and_evaluate()
    return NetworkAnomalyDetector(model_path=MODEL_PATH)


def test_model_artifact_exists_and_loads(detector: NetworkAnomalyDetector):
    """Verify that the model file is serialized and properly loaded."""
    assert os.path.exists(MODEL_PATH), "Model file missing"
    assert detector.is_trained is True
    assert detector.model is not None


def test_normal_baseline_scoring(detector: NetworkAnomalyDetector):
    """Verify normal traffic flows produce low BDI scores (< 0.30) and no false alarms."""
    csv_path = os.path.join(DATA_DIR, "benign_baseline.csv")
    df = pd.read_csv(csv_path)
    records = df.drop(columns=["label"]).to_dict(orient="records")[:50]

    for record in records:
        res = detector.score_flow_dict(record)
        assert res["is_anomaly"] is False
        assert res["bdi_score"] < 0.50
        assert res["status"] in ["NOMINAL", "SUSPICIOUS"]


def test_zero_day_attack_detection(detector: NetworkAnomalyDetector):
    """Verify zero-day non-IoC attacks trigger CRITICAL_ANOMALY with BDI >= 0.70."""
    attacks_path = os.path.join(DATA_DIR, "synthetic_attack_samples.json")
    with open(attacks_path, "r", encoding="utf-8") as f:
        attacks = json.load(f)

    for atk in attacks:
        res = detector.score_flow_dict(atk["flow_data"])
        assert res["is_anomaly"] is True, f"Failed to detect: {atk['name']}"
        assert res["bdi_score"] >= 0.70, f"Score too low for: {atk['name']}"
        assert res["status"] == "CRITICAL_ANOMALY"
        assert len(res["drifted_features"]) > 0


def test_inference_latency_benchmark(detector: NetworkAnomalyDetector):
    """Verify inference latency is < 5ms per vector (NFR-01 requirement)."""
    sample_vec = np.random.uniform(0.0, 1.0, size=(41,))
    
    # Warmup
    detector.score_vector(sample_vec)

    latencies = []
    for _ in range(200):
        t0 = time.perf_counter()
        detector.score_vector(sample_vec)
        latencies.append((time.perf_counter() - t0) * 1000) # in ms

    avg_latency = float(np.mean(latencies))
    p95_latency = float(np.percentile(latencies, 95))

    print(f"\n[LATENCY] Avg: {avg_latency:.3f} ms | P95: {p95_latency:.3f} ms")
    assert avg_latency < 15.0, f"Average inference latency {avg_latency:.3f} ms exceeds 15ms target"


def test_rolling_false_positive_filter():
    """Verify that single transient anomalies are buffered, but 3 consecutive anomalies escalate."""
    rf_filter = RollingFalsePositiveFilter(window_size=3, time_window_seconds=5.0)
    test_ip = "192.168.1.99"

    # Tick 1: Anomaly (Transient spike) -> Should NOT escalate
    t1 = rf_filter.evaluate(test_ip, is_anomaly=True, bdi_score=0.92)
    assert t1["should_escalate"] is False
    assert t1["consecutive_anomalies"] == 1

    # Tick 2: Normal flow (noise passed) -> Reset consecutive count
    t2 = rf_filter.evaluate(test_ip, is_anomaly=False, bdi_score=0.10)
    assert t2["should_escalate"] is False
    assert t2["consecutive_anomalies"] == 0

    # Tick 3, 4, 5: Sustained attack bursts
    t3 = rf_filter.evaluate(test_ip, is_anomaly=True, bdi_score=0.91)
    assert t3["should_escalate"] is False
    assert t3["consecutive_anomalies"] == 1

    t4 = rf_filter.evaluate(test_ip, is_anomaly=True, bdi_score=0.95)
    assert t4["should_escalate"] is False
    assert t4["consecutive_anomalies"] == 2

    t5 = rf_filter.evaluate(test_ip, is_anomaly=True, bdi_score=0.98)
    assert t5["should_escalate"] is True
    assert t5["consecutive_anomalies"] == 3
    assert t5["status"] == "ESCALATE_TO_AGENT"


@pytest.mark.asyncio
async def test_rolling_filter_concurrent_evaluate_async():
    """Verify thread-safe evaluate_async handles concurrent coroutine evaluation."""
    rf_filter = RollingFalsePositiveFilter(window_size=3, time_window_seconds=5.0)
    
    # Run concurrent async evaluations across multiple distinct IPs
    async def feed_ip(ip: str, anomaly: bool):
        return await rf_filter.evaluate_async(ip, is_anomaly=anomaly, bdi_score=0.90 if anomaly else 0.05)

    # Concurrently feed 3 ticks for 2 different IPs
    tasks = []
    for _ in range(3):
        tasks.append(feed_ip("192.168.1.50", True))
        tasks.append(feed_ip("192.168.1.51", False))

    results = await asyncio.gather(*tasks)
    assert len(results) == 6
    
    # Check that the 3rd evaluation of the anomalous IP escalated
    final_anom = await rf_filter.evaluate_async("192.168.1.50", is_anomaly=True, bdi_score=0.95)
    assert final_anom["should_escalate"] is True
    
    # Check that normal IP never escalated
    final_norm = await rf_filter.evaluate_async("192.168.1.51", is_anomaly=False, bdi_score=0.01)
    assert final_norm["should_escalate"] is False
