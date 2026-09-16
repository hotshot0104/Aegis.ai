"""
NSL-KDD Dataset Adapter for Project AEGIS-AI.
Parses KDDTrain+ and KDDTest+ files, extracts 41 statistical non-payload flow metrics
using FlowFeatureExtractor, and separates benign baseline from attack traffic.
"""

import os
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
from backend.ml_engine.feature_extractor import FEATURE_NAMES, FlowFeatureExtractor

# Attack taxonomy mapping for NSL-KDD labels
ATTACK_CATEGORIES = {
    # DoS
    "apache2": "DoS", "back": "DoS", "land": "DoS", "mailbomb": "DoS",
    "neptune": "DoS", "pod": "DoS", "processtable": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe", "mscan": "Probe", "nmap": "Probe",
    "portsweep": "Probe", "saint": "Probe", "satan": "Probe",
    # R2L (Remote to Local)
    "ftp_write": "R2L", "guess_passwd": "R2L", "httptunnel": "R2L",
    "imap": "R2L", "multihop": "R2L", "named": "R2L", "phf": "R2L",
    "sendmail": "R2L", "snmpget": "R2L", "snmpguess": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "worm": "R2L",
    "xlock": "R2L", "xsnoop": "R2L",
    # U2R (User to Root)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "ps": "U2R", "rootkit": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}

COLUMN_NAMES = FEATURE_NAMES + ["label", "difficulty_level"]


class NslKddAdapter:
    """Adapts raw NSL-KDD data into normalized feature matrices for AEGIS-AI."""

    @staticmethod
    def load_dataset(
        train_path: str,
        test_path: str,
        max_train_samples: int = 50000,
        max_test_attacks: int = 15000
    ) -> Dict[str, Any]:
        """
        Loads and normalizes KDDTrain+ and KDDTest+.
        
        Args:
            train_path: Path to KDDTrain+.txt
            test_path: Path to KDDTest+.txt
            max_train_samples: Cap on benign training rows for fast training
            max_test_attacks: Cap on attack evaluation rows
            
        Returns:
            Dict containing:
              - 'train_benign': np.ndarray of shape (N, 41)
              - 'test_benign': np.ndarray of normal test vectors
              - 'test_attacks': np.ndarray of attack test vectors
              - 'test_attack_labels': List of str (attack names)
              - 'test_attack_categories': List of str (DoS, Probe, R2L, U2R)
        """
        if not os.path.exists(train_path):
            raise FileNotFoundError(f"Train file not found: {train_path}")
        if not os.path.exists(test_path):
            raise FileNotFoundError(f"Test file not found: {test_path}")

        print(f"[*] Reading KDDTrain+ from {train_path}...")
        df_train = pd.read_csv(train_path, header=None, names=COLUMN_NAMES)
        
        print(f"[*] Reading KDDTest+ from {test_path}...")
        df_test = pd.read_csv(test_path, header=None, names=COLUMN_NAMES)

        # Separate benign and attack
        train_normal_df = df_train[df_train["label"] == "normal"]
        if max_train_samples and len(train_normal_df) > max_train_samples:
            train_normal_df = train_normal_df.sample(n=max_train_samples, random_state=42)

        test_normal_df = df_test[df_test["label"] == "normal"]
        test_attack_df = df_test[df_test["label"] != "normal"]
        if max_test_attacks and len(test_attack_df) > max_test_attacks:
            test_attack_df = test_attack_df.sample(n=max_test_attacks, random_state=42)

        print(f"[+] KDDTrain+: {len(train_normal_df)} benign samples selected for training")
        print(f"[+] KDDTest+:  {len(test_normal_df)} benign samples (for real-world FP check)")
        print(f"[+] KDDTest+:  {len(test_attack_df)} unseen attack samples (for zero-day detection check)")

        # Extract features using FlowFeatureExtractor to guarantee zero-IoC & exact normalization
        print("[*] Normalizing features using FlowFeatureExtractor...")
        train_benign_records = train_normal_df[FEATURE_NAMES].to_dict(orient="records")
        train_benign_vecs = FlowFeatureExtractor.extract_batch(train_benign_records)

        test_benign_records = test_normal_df[FEATURE_NAMES].to_dict(orient="records")
        test_benign_vecs = FlowFeatureExtractor.extract_batch(test_benign_records)

        test_attack_records = test_attack_df[FEATURE_NAMES].to_dict(orient="records")
        test_attack_vecs = FlowFeatureExtractor.extract_batch(test_attack_records)

        attack_labels = test_attack_df["label"].astype(str).tolist()
        attack_categories = [ATTACK_CATEGORIES.get(lbl, "Unknown/Novel") for lbl in attack_labels]

        return {
            "train_benign": train_benign_vecs,
            "test_benign": test_benign_vecs,
            "test_attacks": test_attack_vecs,
            "test_attack_labels": attack_labels,
            "test_attack_categories": attack_categories,
        }
