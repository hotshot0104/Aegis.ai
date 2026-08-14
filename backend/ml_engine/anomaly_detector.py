"""
Network Anomaly Detector for Project AEGIS-AI.
Unsupervised Perception Engine using Isolation Forest trained exclusively
on benign normal baseline traffic.
Calculates the Behavioral Deviation Index (BDI) on a [0.00, 1.00] scale.
Strictly zero-IoC compliant (Rule 1 & Rule 2).
"""

from typing import Dict, Any, Optional, List, Tuple
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


class NetworkAnomalyDetector:
    """
    Unsupervised statistical perception engine.
    Detects zero-day behavioral compromises using Isolation Forest.
    """

    def __init__(
        self,
        n_estimators: int = 50,
        contamination: float = 0.01,
        random_state: int = 42,
        anomaly_threshold: float = 0.80,
        model_path: Optional[str] = None
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.anomaly_threshold = anomaly_threshold
        self.model_path = model_path or DEFAULT_MODEL_PATH
        
        self.model: Optional[IsolationForest] = None
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

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples="auto",
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
        Transforms raw decision_function score into Behavioral Deviation Index (BDI) in [0.00, 1.00].
        Calibrated for contamination=0.01 (tighter boundary):
        - Normal baseline (raw >= 0.05) maps to low BDI [0.00, 0.40].
        - Suspicious deviation (raw 0.00 to 0.05) maps to [0.50, 0.80].
        - High deviation / Zero-Day attacks (raw < 0.00) map to [0.83, 1.00].
        """
        normalized = (0.05 - raw_score) / 0.10
        return float(np.clip(normalized, 0.0, 1.0))



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
        elif bdi_score >= 0.50:
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
        self.model = joblib.load(path)
        self.is_trained = True
        self.model_path = path
