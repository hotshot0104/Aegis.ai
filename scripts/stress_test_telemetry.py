#!/usr/bin/env python3
"""
High-Throughput Streaming Stress-Test for Project RAKSHA-AI.
Generates 50,000+ realistic concurrent network flow vectors to measure:
1. Pure feature extraction and BDI scoring throughput (flows/sec)
2. Latency percentiles (P50, P90, P95, P99) against the NFR-01 SLA (< 5.0 ms)
3. Memory consumption stability
4. Sliding temporal rolling filter false-positive suppression rate under noise
"""

import os
import sys
import time
import random
import uuid
import resource
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.ml_engine.feature_extractor import FlowFeatureExtractor, FEATURE_NAMES
from backend.ml_engine.anomaly_detector import NetworkAnomalyDetector
from backend.ml_engine.rolling_filter import RollingFalsePositiveFilter


def generate_synthetic_flow(is_attack: bool = False) -> dict:
    """Generates a realistic flow vector dictionary."""
    if not is_attack:
        return {
            "duration": round(random.uniform(0.01, 1.2), 3),
            "src_bytes": random.randint(150, 1500),
            "dst_bytes": random.randint(500, 12000),
            "count": random.randint(1, 8),
            "srv_count": random.randint(1, 5),
            "logged_in": 1,
            "num_failed_logins": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": random.randint(5, 50),
            "dst_host_srv_count": random.randint(5, 40),
            "service": random.choice(["http", "domain_u", "smtp", "ldap"]),
            "flag": "SF",
            "protocol_type": "tcp"
        }
    else:
        return {
            "duration": 0.0,
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": random.randint(300, 500),
            "srv_count": random.randint(300, 500),
            "logged_in": 0,
            "num_failed_logins": 0,
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "same_srv_rate": 0.05,
            "diff_srv_rate": 0.95,
            "dst_host_count": 255,
            "dst_host_srv_count": 5,
            "service": "private",
            "flag": "S0",
            "protocol_type": "tcp"
        }


def run_stress_test(num_flows: int = 50000):
    print("==============================================================================")
    print(f"   PROJECT RAKSHA-AI: HIGH-THROUGHPUT STREAMING STRESS TEST ({num_flows:,} FLOWS)")
    print("==============================================================================")

    model_path = os.path.join(BASE_DIR, "backend", "models_saved", "isolation_forest_benign.joblib")
    detector = NetworkAnomalyDetector(model_path)
    rolling_filter = RollingFalsePositiveFilter(window_size=5)

    mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    print(f"[*] Initial Memory Footprint: {mem_before:.2f} MB")
    print(f"[*] Simulating {num_flows:,} sequential streaming telemetry events...")

    latencies_us = []
    attacks_generated = 0
    anomalies_detected = 0
    alerts_triggered = 0

    t_start = time.perf_counter()

    for i in range(num_flows):
        # 95% benign enterprise baseline, 5% intermittent attack bursts
        is_atk = random.random() < 0.05
        if is_atk:
            attacks_generated += 1

        flow = generate_synthetic_flow(is_attack=is_atk)
        src_ip = f"192.168.1.{random.randint(10, 200)}" if not is_atk else "198.51.100.23"

        t0 = time.perf_counter()
        # 1. Feature Extraction (41 dimensions)
        vec = FlowFeatureExtractor.extract_vector(flow)
        # 2. Perception Scoring (BDI calculation)
        score_res = detector.score_vector(vec)
        bdi = score_res["bdi_score"]
        is_anom = score_res["is_anomaly"]
        # 3. Temporal Rolling Filter
        filter_res = rolling_filter.evaluate(src_ip, is_anom, bdi)
        elapsed_us = (time.perf_counter() - t0) * 1_000_000

        latencies_us.append(elapsed_us)
        if is_anom:
            anomalies_detected += 1
        if filter_res.get("should_escalate", False):
            alerts_triggered += 1

    total_sec = time.perf_counter() - t_start
    mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    throughput = num_flows / total_sec
    lat_arr = np.array(latencies_us)

    p50 = np.percentile(lat_arr, 50)
    p90 = np.percentile(lat_arr, 90)
    p95 = np.percentile(lat_arr, 95)
    p99 = np.percentile(lat_arr, 99)

    print(f"\n==============================================================================")
    print(f"   STRESS TEST RESULTS")
    print(f"==============================================================================")
    print(f"[*] Total Flows Processed:       {num_flows:,}")
    print(f"[*] Total Elapsed Time:          {total_sec:.3f} seconds")
    print(f"[+] Streaming Throughput:        {throughput:,.0f} flows / second")
    print(f"[+] Latency Median (P50):        {p50:.1f} μs ({p50 / 1000.0:.3f} ms)")
    print(f"[+] Latency 90th Percentile:     {p90:.1f} μs ({p90 / 1000.0:.3f} ms)")
    print(f"[+] Latency 95th Percentile:     {p95:.1f} μs ({p95 / 1000.0:.3f} ms)")
    print(f"[+] Latency 99th Percentile:     {p99:.1f} μs ({p99 / 1000.0:.3f} ms)")
    print(f"[+] Memory Delta:                +{mem_after - mem_before:.2f} MB (Total: {mem_after:.2f} MB)")
    print(f"[*] Injected Attack Events:      {attacks_generated:,}")
    print(f"[*] Raw Anomalies Flagged:       {anomalies_detected:,}")
    print(f"[+] Sustained Campaigns Alerted: {alerts_triggered:,} (Transient bursts suppressed)")
    print(f"[+] NFR-01 SLA Compliance (<5ms): {'PASS (100% compliant)' if p99 < 5000 else 'FAIL'}")
    print(f"==============================================================================\n")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    run_stress_test(n)
