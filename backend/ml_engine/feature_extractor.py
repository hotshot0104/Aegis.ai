"""
Feature Extractor Module for Project AEGIS-AI.
Extracts, formats, and normalizes 41 non-payload statistical flow metrics
following the NSL-KDD / CIC-IDS2017 flow taxonomy.
Strictly zero-IoC compliant (Rule 1 & Rule 2).
"""

from typing import Dict, List, Any, Union
import numpy as np

# 41 Statistical Non-Payload Flow Features
FEATURE_NAMES: List[str] = [
    # 1-6: Basic Flow Characteristics
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    # 7-11: Content-Agnostic / Connection Indicators
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    # 12-22: Host State & Login Context
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    # 23-31: Time-Window Traffic Statistics (Past 2 Seconds)
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    # 32-41: Host & Subnet Traversal Statistics
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# Categorical mappings
PROTOCOL_MAP: Dict[str, float] = {"tcp": 0.0, "udp": 0.5, "icmp": 1.0}
SERVICE_MAP: Dict[str, float] = {
    "http": 0.1,
    "smtp": 0.2,
    "dns": 0.3,
    "ftp": 0.4,
    "ssh": 0.5,
    "smb": 0.6,
    "telnet": 0.7,
    "private": 0.8,
    "other": 0.9,
}
FLAG_MAP: Dict[str, float] = {
    "SF": 0.0,    # Normal SYN/FIN established and closed
    "S0": 0.25,   # Connection attempt seen, no reply (potential scan)
    "REJ": 0.5,   # Connection rejected
    "RSTO": 0.75, # Connection reset by originator
    "SH": 1.0,    # SYN-ACK half open
}

# Normalization upper bounds for continuous statistical metrics
FEATURE_SCALING_BOUNDS: Dict[str, float] = {
    "duration": 3600.0,
    "src_bytes": 1000000.0,
    "dst_bytes": 1000000.0,
    "count": 512.0,
    "srv_count": 512.0,
    "dst_host_count": 255.0,
    "dst_host_srv_count": 255.0,
    "hot": 30.0,
    "num_failed_logins": 5.0,
    "num_compromised": 10.0,
    "num_root": 10.0,
    "num_file_creations": 10.0,
    "num_shells": 5.0,
    "num_access_files": 10.0,
}


class FlowFeatureExtractor:
    """Extracts, validates, and normalizes 41 statistical non-payload flow metrics."""

    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Returns the ordered list of 41 feature names."""
        return list(FEATURE_NAMES)

    @classmethod
    def normalize_value(cls, name: str, value: Any) -> float:
        """Normalizes a single flow metric into a float in the range [0.0, 1.0]."""
        if value is None:
            return 0.0

        # Handle Categoricals
        if name == "protocol_type":
            str_val = str(value).strip().lower()
            return PROTOCOL_MAP.get(str_val, 0.0)

        if name == "service":
            str_val = str(value).strip().lower()
            return SERVICE_MAP.get(str_val, 0.9)

        if name == "flag":
            str_val = str(value).strip().upper()
            return FLAG_MAP.get(str_val, 0.0)

        # Handle Numerics
        try:
            float_val = float(value)
        except (ValueError, TypeError):
            return 0.0

        if name in FEATURE_SCALING_BOUNDS:
            max_val = FEATURE_SCALING_BOUNDS[name]
            return float(np.clip(float_val / max_val, 0.0, 1.0))

        # Rates and binary flags are already naturally in [0.0, 1.0]
        return float(np.clip(float_val, 0.0, 1.0))

    @classmethod
    def extract_vector(cls, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Extracts and normalizes a 41-dimensional feature vector from a raw flow dictionary.
        Returns a 1D NumPy float64 array of shape (41,).
        """
        vector = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
        for idx, feature_name in enumerate(FEATURE_NAMES):
            raw_val = flow_dict.get(feature_name, 0.0)
            vector[idx] = cls.normalize_value(feature_name, raw_val)
        return vector

    @classmethod
    def extract_batch(cls, flow_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extracts and normalizes an N x 41 feature matrix from a list of flow dictionaries.
        Returns a 2D NumPy float64 array of shape (N, 41).
        """
        if not flow_list:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
        return np.vstack([cls.extract_vector(flow) for flow in flow_list])
