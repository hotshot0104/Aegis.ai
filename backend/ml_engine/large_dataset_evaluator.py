"""
Large-Scale Dataset Evaluator for Project RAKSHA-AI.
Evaluates RAKSHA-AI anomaly detection models across the complete 148,517-flow corpus
(KDDTrain+ and KDDTest+ combined), including the notoriously challenging KDDTest-21
stealth zero-day subset.

Strictly zero-IoC compliant (Rule 1 & Rule 2).
High-speed vectorized batch execution.
"""

import os
import sys
import time
import json
from typing import Dict, Any, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import numpy as np
import pandas as pd
import joblib

from backend.ml_engine.feature_extractor import (
    FEATURE_NAMES,
    PROTOCOL_MAP,
    SERVICE_MAP,
    FLAG_MAP,
    FEATURE_SCALING_BOUNDS,
)
from backend.ml_engine.anomaly_detector import SubspaceEnsembleIF, NetworkAnomalyDetector

ATTACK_CATEGORIES: Dict[str, str] = {
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


class LargeDatasetEvaluator:
    """High-performance batch evaluator for RAKSHA-AI across 148,000+ flows."""

    def __init__(self, train_path: str, test_path: str):
        self.train_path = train_path
        self.test_path = test_path
        self.df_train: pd.DataFrame = pd.DataFrame()
        self.df_test: pd.DataFrame = pd.DataFrame()
        self.df_all: pd.DataFrame = pd.DataFrame()
        self.X_all: np.ndarray = np.empty((0, 41))

    @staticmethod
    def vectorize_features(df: pd.DataFrame) -> np.ndarray:
        """Vectorized feature transformation converting raw DataFrame to normalized (N, 41) matrix."""
        n_rows = len(df)
        X = np.zeros((n_rows, len(FEATURE_NAMES)), dtype=np.float64)

        for i, col in enumerate(FEATURE_NAMES):
            series = df[col]
            if col == "protocol_type":
                mapped = series.str.strip().str.lower().map(PROTOCOL_MAP).fillna(0.0)
                X[:, i] = mapped.values
            elif col == "service":
                mapped = series.str.strip().str.lower().map(SERVICE_MAP).fillna(0.9)
                X[:, i] = mapped.values
            elif col == "flag":
                mapped = series.str.strip().str.upper().map(FLAG_MAP).fillna(0.0)
                X[:, i] = mapped.values
            else:
                num_vals = pd.to_numeric(series, errors="coerce").fillna(0.0).values
                if col in FEATURE_SCALING_BOUNDS:
                    max_bound = FEATURE_SCALING_BOUNDS[col]
                    scaled = num_vals / max_bound
                    X[:, i] = np.clip(scaled, 0.0, 1.0)
                else:
                    X[:, i] = np.clip(num_vals, 0.0, 1.0)

        return X

    def load_and_prepare(self):
        """Loads both datasets and builds the combined 148,517-flow corpus."""
        print(f"[*] Loading KDDTrain+ from: {self.train_path}")
        self.df_train = pd.read_csv(self.train_path, header=None, names=COLUMN_NAMES)
        self.df_train["split"] = "train"

        print(f"[*] Loading KDDTest+ from: {self.test_path}")
        self.df_test = pd.read_csv(self.test_path, header=None, names=COLUMN_NAMES)
        self.df_test["split"] = "test"

        self.df_all = pd.concat([self.df_train, self.df_test], ignore_index=True)
        print(f"[+] Combined Dataset Loaded: {len(self.df_all):,} total network flows")
        print(f"    - Benign Baseline: {(self.df_all['label'] == 'normal').sum():,} flows")
        print(f"    - Attack Telemetry: {(self.df_all['label'] != 'normal').sum():,} flows")

        print("[*] Performing high-speed vectorized feature extraction (41 non-payload metrics)...")
        t0 = time.time()
        self.X_all = self.vectorize_features(self.df_all)
        print(f"[+] Feature Extraction Complete in {time.time() - t0:.2f}s! Matrix shape: {self.X_all.shape}")

    def evaluate_model(
        self,
        model_name: str,
        predict_fn,
        threshold: float = 0.50
    ) -> Dict[str, Any]:
        """Evaluates a model across the Full Corpus, Held-Out Test, and KDDTest-21."""
        print(f"\n==============================================================================")
        print(f"   BENCHMARKING: {model_name}")
        print(f"==============================================================================")

        t_start = time.perf_counter()
        raw_scores = predict_fn(self.X_all)
        inference_sec = time.perf_counter() - t_start
        throughput_fps = len(self.X_all) / max(0.0001, inference_sec)
        latency_us = (inference_sec / len(self.X_all)) * 1_000_000

        print(f"[+] Inference Complete: {len(self.X_all):,} flows in {inference_sec:.2f}s")
        print(f"    - Throughput: {throughput_fps:,.0f} flows/sec")
        print(f"    - Per-Flow Latency: {latency_us:.1f} microseconds ({latency_us / 1000.0:.3f} ms)")

        # Threshold to binary predictions
        is_anomaly = raw_scores >= threshold

        labels = self.df_all["label"].values
        is_attack = labels != "normal"
        categories = np.array([ATTACK_CATEGORIES.get(lbl, "Unknown/Novel") if lbl != "normal" else "Normal" for lbl in labels])
        splits = self.df_all["split"].values
        difficulty = pd.to_numeric(self.df_all["difficulty_level"], errors="coerce").fillna(21).values

        # 1. Full Corpus Metrics
        total_attacks = is_attack.sum()
        detected_attacks = (is_anomaly & is_attack).sum()
        total_benign = (~is_attack).sum()
        false_alarms = (is_anomaly & (~is_attack)).sum()

        full_recall = (detected_attacks / total_attacks) * 100.0 if total_attacks else 0.0
        full_fpr = (false_alarms / total_benign) * 100.0 if total_benign else 0.0

        # 2. Test Set Metrics (Held-Out 22,544)
        test_mask = splits == "test"
        test_atk_mask = test_mask & is_attack
        test_ben_mask = test_mask & (~is_attack)

        test_recall = (is_anomaly[test_atk_mask].sum() / test_atk_mask.sum()) * 100.0 if test_atk_mask.sum() else 0.0
        test_fpr = (is_anomaly[test_ben_mask].sum() / test_ben_mask.sum()) * 100.0 if test_ben_mask.sum() else 0.0

        # 3. KDDTest-21 Hard Subset Metrics (Difficulty < 21)
        test_21_mask = test_mask & is_attack & (difficulty < 21)
        test_21_recall = (is_anomaly[test_21_mask].sum() / test_21_mask.sum()) * 100.0 if test_21_mask.sum() else 0.0

        # 4. Threat Family Breakdown on Full Corpus
        family_results = {}
        for fam in ["DoS", "Probe", "R2L", "U2R"]:
            fam_mask = categories == fam
            fam_total = fam_mask.sum()
            fam_detected = (is_anomaly & fam_mask).sum()
            fam_recall = (fam_detected / fam_total) * 100.0 if fam_total else 0.0
            family_results[fam] = {
                "total": int(fam_total),
                "detected": int(fam_detected),
                "recall_pct": round(fam_recall, 2)
            }

        # 5. Threat Family Breakdown on Held-Out Test Set
        test_family_results = {}
        for fam in ["DoS", "Probe", "R2L", "U2R"]:
            fam_mask = test_mask & (categories == fam)
            fam_total = fam_mask.sum()
            fam_detected = (is_anomaly & fam_mask).sum()
            fam_recall = (fam_detected / fam_total) * 100.0 if fam_total else 0.0
            test_family_results[fam] = {
                "total": int(fam_total),
                "detected": int(fam_detected),
                "recall_pct": round(fam_recall, 2)
            }

        print(f"\n--- Benchmark Results for {model_name} ---")
        print(f"| Metric / Scope                  | Result Value |")
        print(f"|:--------------------------------|:-------------|")
        print(f"| Total Flows Evaluated           | {len(self.X_all):,} |")
        print(f"| **Full Corpus Attack Recall**   | **{full_recall:.2f}%** ({detected_attacks:,} / {total_attacks:,}) |")
        print(f"| Full Corpus False Alarm Rate    | {full_fpr:.2f}% ({false_alarms:,} / {total_benign:,}) |")
        print(f"| **Held-Out Test Set Recall**    | **{test_recall:.2f}%** ({is_anomaly[test_atk_mask].sum():,} / {test_atk_mask.sum():,}) |")
        print(f"| Held-Out Test False Alarm Rate  | {test_fpr:.2f}% ({is_anomaly[test_ben_mask].sum():,} / {test_ben_mask.sum():,}) |")
        print(f"| **KDDTest-21 Stealth Recall**   | **{test_21_recall:.2f}%** ({is_anomaly[test_21_mask].sum():,} / {test_21_mask.sum():,}) |")
        print(f"| DoS Recall (Full)               | {family_results['DoS']['recall_pct']}% |")
        print(f"| Probe Recon Recall (Full)       | {family_results['Probe']['recall_pct']}% |")
        print(f"| R2L Brute-Force Recall (Full)   | {family_results['R2L']['recall_pct']}% |")
        print(f"| U2R Rootkit Recall (Full)       | {family_results['U2R']['recall_pct']}% |")

        return {
            "model_name": model_name,
            "total_flows": int(len(self.X_all)),
            "inference_duration_sec": round(inference_sec, 3),
            "throughput_flows_per_sec": round(throughput_fps, 1),
            "latency_microseconds": round(latency_us, 2),
            "full_corpus": {
                "total_attacks": int(total_attacks),
                "detected_attacks": int(detected_attacks),
                "recall_pct": round(full_recall, 2),
                "total_benign": int(total_benign),
                "false_alarms": int(false_alarms),
                "false_positive_pct": round(full_fpr, 2),
            },
            "held_out_test": {
                "total_attacks": int(test_atk_mask.sum()),
                "detected_attacks": int(is_anomaly[test_atk_mask].sum()),
                "recall_pct": round(test_recall, 2),
                "total_benign": int(test_ben_mask.sum()),
                "false_alarms": int(is_anomaly[test_ben_mask].sum()),
                "false_positive_pct": round(test_fpr, 2),
            },
            "kdd_test_21_stealth": {
                "total_attacks": int(test_21_mask.sum()),
                "detected_attacks": int(is_anomaly[test_21_mask].sum()),
                "recall_pct": round(test_21_recall, 2),
            },
            "family_breakdown_full": family_results,
            "family_breakdown_test": test_family_results,
        }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    train_path = os.path.join(base_dir, "backend", "data", "nslkdd", "KDDTrain+.txt")
    test_path = os.path.join(base_dir, "backend", "data", "nslkdd", "KDDTest+.txt")
    output_dir = os.path.join(base_dir, "backend", "models_saved", "kaggle_artifacts")
    report_file = os.path.join(output_dir, "large_dataset_148k_report.json")

    evaluator = LargeDatasetEvaluator(train_path, test_path)
    evaluator.load_and_prepare()

    results = {}

    # 1. Model 1: Production Baseline Isolation Forest
    m1_path = os.path.join(base_dir, "backend", "models_saved", "isolation_forest_benign.joblib")
    if os.path.exists(m1_path):
        m1_detector = NetworkAnomalyDetector(m1_path)
        def predict_m1(X):
            batch_res = m1_detector.score_batch(X)
            return batch_res["bdi_scores"]

        results["v1_isolation_forest"] = evaluator.evaluate_model(
            "RAKSHA-AI V1: Production Isolation Forest",
            predict_m1,
            threshold=m1_detector.anomaly_threshold
        )

    # 2. Model 2: Subspace Ensemble Isolation Forest (Calibrated on Benign Baseline)
    m2_path = os.path.join(output_dir, "isolation_forest_subspace_ensemble.joblib")
    if os.path.exists(m2_path):
        m2_ensemble = joblib.load(m2_path)
        # Calibrate threshold on benign train partition to hold false positive rate <= 2.5%
        benign_train_mask = (evaluator.df_all["split"] == "train") & (evaluator.df_all["label"] == "normal")
        benign_train_X = evaluator.X_all[benign_train_mask]
        benign_scores = m2_ensemble.decision_function(benign_train_X)
        calibrated_cutoff = np.percentile(benign_scores, 2.5)  # 2.5% FP limit on baseline
        print(f"[*] Subspace Ensemble Calibrated Decision Cutoff (at 2.5% FP): {calibrated_cutoff:.5f}")

        def predict_m2(X):
            raw_scores = m2_ensemble.decision_function(X)
            # Normal flows have score >= cutoff (BDI < 0.70); Anomalies have score < cutoff (BDI >= 0.70)
            bdi = np.where(
                raw_scores >= calibrated_cutoff,
                0.20 + np.clip(calibrated_cutoff - raw_scores, -0.20, 0.45),
                0.70 + np.clip((calibrated_cutoff - raw_scores) * 2.0, 0.0, 0.28)
            )
            return bdi

        results["v4_subspace_ensemble"] = evaluator.evaluate_model(
            "RAKSHA-AI V4: Subspace Ensemble Isolation Forest",
            predict_m2,
            threshold=0.70
        )

    # Save comprehensive report
    os.makedirs(output_dir, exist_ok=True)
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Full 148,517-flow benchmark report saved to: {report_file}")


if __name__ == "__main__":
    main()
