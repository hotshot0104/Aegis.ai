"""
Network Anomaly Detector for Project RAKSHA-AI.
Unsupervised Perception Engine using Isolation Forest trained exclusively
on benign normal baseline traffic.
Calculates the Behavioral Deviation Index (BDI) on a [0.00, 1.00] scale.
Strictly zero-IoC compliant (Rule 1 & Rule 2).
"""

from typing import Dict, Any, Optional
import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from backend.ml_engine.feature_extractor import FEATURE_NAMES, FlowFeatureExtractor

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models_saved",
    "isolation_forest_benign.joblib"
)


class SubspaceEnsembleIF:
    """
    Subspace Ensemble of Isolation Forests.
    Trains 3 specialist models on distinct feature subsets to overcome axis-aligned cut bias
    and improve detection of subtle anomalies in specific domains.
    """
    def __init__(self, n_estimators=10, max_samples=256, contamination=0.01, random_state=42, n_jobs=1):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.n_jobs = n_jobs
        self._ensure_indices()
        
        # Initialize the 4 models
        self.models = {
            "volume": IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples, contamination=self.contamination, random_state=self.random_state, n_jobs=self.n_jobs),
            "time_flags": IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples, contamination=self.contamination, random_state=self.random_state+1, n_jobs=self.n_jobs),
            "topology": IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples, contamination=self.contamination, random_state=self.random_state+2, n_jobs=self.n_jobs),
            "auth": IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples, contamination=self.contamination, random_state=self.random_state+3, n_jobs=self.n_jobs)
        }

        if not hasattr(self, "volume_idx") or not hasattr(self, "topology_idx") or not hasattr(self, "auth_idx") or not hasattr(self, "time_flags_idx"):
            self.volume_features = [
                "src_bytes", "dst_bytes", "duration", "count", "srv_count"
            ]
            self.time_flags_features = [
                "flag", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
                "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate"
            ]
            self.topology_features = [
                "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
                "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
                "dst_host_srv_diff_host_rate", "dst_host_serror_rate", 
                "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
            ]
            self.auth_features = [
                "num_failed_logins", "logged_in", "service", "root_shell",
                "is_guest_login", "su_attempted", "protocol_type", "hot", "num_compromised",
                "num_root", "num_file_creations", "num_shells", "num_access_files",
                "is_host_login", "num_outbound_cmds"
            ]
            self.volume_idx = [FEATURE_NAMES.index(f) for f in self.volume_features if f in FEATURE_NAMES]
            self.time_flags_idx = [FEATURE_NAMES.index(f) for f in self.time_flags_features if f in FEATURE_NAMES]
            self.topology_idx = [FEATURE_NAMES.index(f) for f in self.topology_features if f in FEATURE_NAMES]
            self.auth_idx = [FEATURE_NAMES.index(f) for f in self.auth_features if f in FEATURE_NAMES]

            # If unpickled from Kaggle cloud notebook, auth model was trained on 19 features:
            auth_model = self.models.get("auth") if hasattr(self, "models") else None
            if auth_model is not None and getattr(auth_model, "n_features_in_", 0) == 19:
                self.volume_idx = [0, 1, 2, 19, 20]
                self.topology_idx = list(range(21, 38))
                self.auth_idx = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 38, 39, 40]

    def fit(self, X):
        """Fit all 4 specialist models."""
        self._ensure_indices()
        vol_model = self.models.get("volume") or self.models.get("vol")
        time_flags_model = self.models.get("time_flags")
        top_model = self.models.get("topology") or self.models.get("top")
        auth_model = self.models.get("auth")

        vol_model.fit(X[:, self.volume_idx])
        if time_flags_model: time_flags_model.fit(X[:, self.time_flags_idx])
        top_model.fit(X[:, self.topology_idx])
        auth_model.fit(X[:, self.auth_idx])
        return self

    def decision_function(self, X):
        """
        Score using all 4 models. 
        IsolationForest returns lower (negative) values for anomalies.
        We return the minimum score across the models (the most anomalous score).
        """
        self._ensure_indices()
        vol_model = self.models.get("volume") or self.models.get("vol")
        time_flags_model = self.models.get("time_flags")
        top_model = self.models.get("topology") or self.models.get("top")
        auth_model = self.models.get("auth")

        score_vol = vol_model.decision_function(X[:, self.volume_idx])
        score_top = top_model.decision_function(X[:, self.topology_idx])
        score_auth = auth_model.decision_function(X[:, self.auth_idx])
        
        scores = [score_vol, score_top, score_auth]
        if time_flags_model:
            scores.append(time_flags_model.decision_function(X[:, self.time_flags_idx]))
            
        # Stack scores and find the minimum per row
        stacked = np.vstack(scores)
        return np.min(stacked, axis=0)


# Register SubspaceEnsembleIF in sys.modules['__main__'] for seamless unpickling of cloud-trained models
import sys
if '__main__' in sys.modules and not hasattr(sys.modules['__main__'], 'SubspaceEnsembleIF'):
    setattr(sys.modules['__main__'], 'SubspaceEnsembleIF', SubspaceEnsembleIF)


class NetworkAnomalyDetector:
    """
    Unsupervised statistical perception engine.
    Detects zero-day behavioral compromises using Isolation Forest.
    """

    def __init__(
        self,
        n_estimators: int = 10,
        max_samples: int = 256,
        contamination: float = 0.01,
        random_state: int = 42,
        anomaly_threshold: float = 0.70,
        model_path: Optional[str] = None
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.anomaly_threshold = anomaly_threshold
        self.model_path = model_path or DEFAULT_MODEL_PATH
        
        self.model: Optional[SubspaceEnsembleIF] = None
        self.is_trained: bool = False

        # Attempt to load saved model if present
        if os.path.exists(self.model_path):
            self.load_model(self.model_path)

    def train_on_benign_traffic(self, normal_features: np.ndarray) -> Dict[str, Any]:
        """
        Trains the Isolation Forest strictly on benign/normal network flow vectors.
        
        Args:
            normal_features: 2D NumPy array of shape (N, 41) representing benign samples.
            
        Returns:
            Dict with training metadata.
        """
        if normal_features.ndim != 2 or normal_features.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Expected features shape (N, {len(FEATURE_NAMES)}), got {normal_features.shape}"
            )

        self.model = SubspaceEnsembleIF(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1
        )
        self.model.fit(normal_features)
        self.is_trained = True

        # Save trained artifact
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)

        return {
            "status": "TRAINED_SUCCESS",
            "samples_trained": normal_features.shape[0],
            "feature_dim": normal_features.shape[1],
            "contamination": self.contamination,
            "model_path": self.model_path
        }

    def compute_bdi(self, raw_score: float) -> float:
        """
        Transforms raw decision_function score into Behavioral Deviation Index (BDI) in [0.00, 0.98].
        Piecewise calibration for contamination=0.01:
        - Normal baseline (raw >= 0.05):         BDI [0.00, 0.30]
        - Suspicious deviation (0.00 <= raw < 0.05): BDI [0.30, 0.70]
        - High deviation / Zero-Day (raw < 0.00):   BDI [0.70, 0.98]
        Capped at 0.98 to prevent saturation at exactly 1.00.
        """
        if raw_score >= 0.05:
            # Normal: map [0.05, +inf) -> [0.00, 0.30]
            # Higher raw_score = more normal = lower BDI
            bdi = max(0.0, 0.30 - (raw_score - 0.05) * 3.0)
        elif raw_score >= 0.00:
            # Suspicious: map [0.00, 0.05) -> [0.30, 0.70]
            bdi = 0.30 + (0.05 - raw_score) * 8.0
        else:
            # Anomalous: map [-0.20, 0.00) -> [0.70, 0.98]
            bdi = 0.70 + min(0.28, abs(raw_score) * 1.4)
        return round(max(0.0, min(0.98, bdi)), 4)

    def compute_bdi_batch(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Vectorized transformation of raw decision_function scores into BDI array in [0.00, 0.98].
        """
        raw = np.asarray(raw_scores, dtype=np.float64)
        bdi = np.empty_like(raw)

        m1 = raw >= 0.05
        bdi[m1] = np.maximum(0.0, 0.30 - (raw[m1] - 0.05) * 3.0)

        m2 = (raw >= 0.00) & (~m1)
        bdi[m2] = 0.30 + (0.05 - raw[m2]) * 8.0

        m3 = raw < 0.00
        bdi[m3] = 0.70 + np.minimum(0.28, np.abs(raw[m3]) * 1.4)

        return np.clip(np.round(bdi, 4), 0.0, 0.98)

    def score_batch(self, feature_matrix: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Vectorized scoring of an (N, 41) feature matrix.
        Returns dict containing arrays: raw_scores, bdi_scores, is_anomaly.
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model is not trained. Call train_on_benign_traffic or load a model.")

        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Feature matrix must have shape (N, {len(FEATURE_NAMES)}), got {feature_matrix.shape}"
            )

        raw_scores = self.model.decision_function(feature_matrix)
        bdi_scores = self.compute_bdi_batch(raw_scores)
        is_anomaly = bdi_scores >= self.anomaly_threshold

        return {
            "raw_scores": raw_scores,
            "bdi_scores": bdi_scores,
            "is_anomaly": is_anomaly
        }

    def score_vector(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Scores a single 41-feature flow vector.
        
        Args:
            feature_vector: 1D array of shape (41,) or 2D array of shape (1, 41).
            
        Returns:
            Dict containing bdi_score, is_anomaly, status, and drifted features.
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model is not trained. Call train_on_benign_traffic or load a model.")

        if feature_vector.ndim == 1:
            vec = feature_vector.reshape(1, -1)
        else:
            vec = feature_vector

        if vec.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Feature vector must have {len(FEATURE_NAMES)} dimensions, got {vec.shape[1]}"
            )

        raw_score = float(self.model.decision_function(vec)[0])
        bdi_score = round(self.compute_bdi(raw_score), 4)
        is_anomaly = bool(bdi_score >= self.anomaly_threshold)

        if bdi_score >= self.anomaly_threshold:
            status = "CRITICAL_ANOMALY"
        elif bdi_score >= 0.30:
            status = "SUSPICIOUS"
        else:
            status = "NOMINAL"

        # Identify top drifted non-zero features for explainability
        flat_vec = vec[0]
        drifted_features = {
            FEATURE_NAMES[i]: round(float(flat_vec[i]), 4)
            for i in range(len(FEATURE_NAMES))
            if flat_vec[i] > 0.40  # Flag prominently high statistical metrics
        }

        return {
            "bdi_score": bdi_score,
            "raw_decision_score": round(raw_score, 4),
            "is_anomaly": is_anomaly,
            "status": status,
            "drifted_features": drifted_features
        }

    def score_flow_dict(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience method to extract features from a raw flow dict and score it."""
        vector = FlowFeatureExtractor.extract_vector(flow_dict)
        result = self.score_vector(vector)
        result["src_ip"] = flow_dict.get("src_ip", "UNKNOWN")
        result["dst_ip"] = flow_dict.get("dst_ip", "UNKNOWN")
        result["dst_port"] = flow_dict.get("dst_port", 0)
        return result

    def save_model(self, path: Optional[str] = None) -> str:
        """Saves the serialized model artifact."""
        if not self.is_trained or self.model is None:
            raise RuntimeError("Cannot save an untrained model.")
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump(self.model, save_path)
        return save_path

    def load_model(self, path: str) -> None:
        """Loads a serialized model artifact."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found at: {path}")
        if '__main__' in sys.modules and not hasattr(sys.modules['__main__'], 'SubspaceEnsembleIF'):
            setattr(sys.modules['__main__'], 'SubspaceEnsembleIF', SubspaceEnsembleIF)
        self.model = joblib.load(path)
        self.is_trained = True
        self.model_path = path
