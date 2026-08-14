"""
Unit Tests for FlowFeatureExtractor and Phase 0 Data Quality.
Ensures zero-IoC compliance, 41-feature dimensions, and normalization properties.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from backend.ml_engine.feature_extractor import FlowFeatureExtractor, FEATURE_NAMES

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend", "data")


def test_feature_extractor_dimensions():
    """Verify that the feature extractor extracts exactly 41 dimensions."""
    sample_flow = {
        "duration": 1.5,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 450,
        "dst_bytes": 3200,
        "count": 5,
        "srv_count": 4,
    }
    vector = FlowFeatureExtractor.extract_vector(sample_flow)
    
    assert isinstance(vector, np.ndarray)
    assert vector.shape == (41,)
    assert len(FlowFeatureExtractor.get_feature_names()) == 41


def test_feature_normalization_bounds():
    """Verify all normalized feature values are strictly inside [0.0, 1.0]."""
    test_flows = [
        {"duration": 1000000.0, "src_bytes": 999999999, "count": 9999}, # extreme upper bound
        {"duration": -50.0, "src_bytes": -100, "count": -5},             # negative lower bound
        {"protocol_type": "unknown", "service": "invalid", "flag": "XYZ"}, # unknown categoricals
        {}, # empty dict
    ]
    
    batch_matrix = FlowFeatureExtractor.extract_batch(test_flows)
    assert batch_matrix.shape == (4, 41)
    assert np.all(batch_matrix >= 0.0)
    assert np.all(batch_matrix <= 1.0)
    assert not np.isnan(batch_matrix).any()


def test_benign_baseline_dataset_integrity():
    """Verify benign_baseline.csv dataset has 5000 rows, 0 NaNs, and 100% normal labels."""
    csv_path = os.path.join(DATA_DIR, "benign_baseline.csv")
    assert os.path.exists(csv_path), "benign_baseline.csv missing"
    
    df = pd.read_csv(csv_path)
    assert len(df) >= 5000
    assert "label" in df.columns
    assert (df["label"] == "normal").all(), "Training partition must contain ONLY normal records (Rule 2)"
    assert df.isnull().sum().sum() == 0, "Dataset must not contain NaN values"
    
    # Verify vector extraction on dataset
    records = df.drop(columns=["label"]).to_dict(orient="records")
    extracted_features = FlowFeatureExtractor.extract_batch(records)
    assert extracted_features.shape == (len(df), 41)
    assert np.all((extracted_features >= 0.0) & (extracted_features <= 1.0))


def test_synthetic_attack_samples_present():
    """Verify synthetic attack samples are present with required MITRE metadata."""
    json_path = os.path.join(DATA_DIR, "synthetic_attack_samples.json")
    assert os.path.exists(json_path), "synthetic_attack_samples.json missing"
    
    with open(json_path, "r", encoding="utf-8") as f:
        attacks = json.load(f)
    
    assert len(attacks) >= 3
    for attack in attacks:
        assert "attack_id" in attack
        assert "mitre_id" in attack
        assert "flow_data" in attack
        vector = FlowFeatureExtractor.extract_vector(attack["flow_data"])
        assert vector.shape == (41,)


def test_asset_inventory_and_mitre_kb_present():
    """Verify asset registry and MITRE knowledge base exist and are valid JSON."""
    asset_path = os.path.join(DATA_DIR, "asset_inventory.json")
    mitre_path = os.path.join(DATA_DIR, "mitre_attack_kb.json")
    
    assert os.path.exists(asset_path)
    assert os.path.exists(mitre_path)
    
    with open(asset_path, "r", encoding="utf-8") as f:
        assets = json.load(f)
    assert len(assets) >= 5
    assert "192.168.1.45" in assets
    assert assets["192.168.1.45"]["criticality_level"] == "CRITICAL_TIER_1"
    
    with open(mitre_path, "r", encoding="utf-8") as f:
        mitre = json.load(f)
    assert len(mitre) >= 4
    mitre_ids = [m["technique_id"] for m in mitre]
    assert "T1021.002" in mitre_ids
