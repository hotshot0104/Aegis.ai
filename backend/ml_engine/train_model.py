"""
Model Training & Evaluation Script for Project AEGIS-AI.
Trains Isolation Forest exclusively on benign baseline data (backend/data/benign_baseline.csv)
and evaluates detection capability against synthetic zero-day attack samples.
"""

import os
import sys
import json
import pandas as pd
import numpy as np

# Bootstrap project root to sys.path for direct script execution
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ml_engine.feature_extractor import FlowFeatureExtractor
from backend.ml_engine.anomaly_detector import NetworkAnomalyDetector

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models_saved")
os.makedirs(MODELS_DIR, exist_ok=True)


def train_and_evaluate() -> None:
    csv_path = os.path.join(DATA_DIR, "benign_baseline.csv")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Benign dataset missing at {csv_path}. Run generate_baseline_data.py first.")

    print(f"[*] Loading benign baseline from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Invariant Rule 2 check
    assert (df["label"] == "normal").all(), "FATAL: Training data contains non-normal labels!"
    
    records = df.drop(columns=["label"]).to_dict(orient="records")
    normal_features = FlowFeatureExtractor.extract_batch(records)
    print(f"[+] Extracted {normal_features.shape[0]} samples with {normal_features.shape[1]} non-payload features.")

    # Initialize and train Isolation Forest
    model_path = os.path.join(MODELS_DIR, "isolation_forest_benign.joblib")
    detector = NetworkAnomalyDetector(
        n_estimators=50,
        contamination=0.01,
        random_state=42,
        anomaly_threshold=0.80,
        model_path=model_path
    )
    
    print("[*] Training Isolation Forest on benign baseline...")
    train_res = detector.train_on_benign_traffic(normal_features)
    print(f"[+] Model trained and saved to {train_res['model_path']}")

    # Benchmark on a sample slice of benign records
    print("\n--- 1. Benign Normal Baseline Benchmark ---")
    sample_normal = records[:5]
    for idx, sample in enumerate(sample_normal):
        res = detector.score_flow_dict(sample)
        print(f"  [Normal Sample #{idx+1}] Service: {sample['service']} | BDI: {res['bdi_score']} | Status: {res['status']} | Is Anomaly: {res['is_anomaly']}")
        assert res["bdi_score"] < 0.40, f"False positive on normal sample! Score: {res['bdi_score']}"

    # Benchmark on ground-truth zero-day attack samples
    print("\n--- 2. Synthetic Zero-Day Non-IoC Attack Benchmark ---")
    attacks_path = os.path.join(DATA_DIR, "synthetic_attack_samples.json")
    with open(attacks_path, "r", encoding="utf-8") as f:
        attacks = json.load(f)

    for atk in attacks:
        res = detector.score_flow_dict(atk["flow_data"])
        print(f"  [Zero-Day Attack: {atk['name']} ({atk['mitre_id']})]")
        print(f"    -> BDI Score: {res['bdi_score']} | Status: {res['status']} | Is Anomaly: {res['is_anomaly']}")
        print(f"    -> Drifted Features: {list(res['drifted_features'].keys())}")
        assert res["is_anomaly"] is True, f"Failed to detect attack {atk['name']}!"
        assert res["bdi_score"] >= 0.80, f"BDI score too low for zero-day attack: {res['bdi_score']}"

    print("\n[SUCCESS] Phase 1 Model Training & Validation SUCCESSFUL!")


if __name__ == "__main__":
    train_and_evaluate()
