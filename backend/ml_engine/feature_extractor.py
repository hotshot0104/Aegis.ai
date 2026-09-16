"""
Feature Extractor Module for Project AEGIS-AI.
Extracts, formats, and normalizes 41 non-payload statistical flow metrics
following the NSL-KDD / CIC-IDS2017 flow taxonomy.
Strictly zero-IoC compliant (Rule 1 & Rule 2).
"""

from typing import Dict, List, Any
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
    # Web & standard services
    "http": 0.10, "http_443": 0.11, "http_2784": 0.12, "http_8001": 0.13, "smtp": 0.20,
    # Name & lookup
    "dns": 0.30, "domain": 0.28, "domain_u": 0.29, "name": 0.26, "csnet_ns": 0.27, "hostnames": 0.25,
    # File transfer
    "ftp": 0.40, "ftp_data": 0.45, "tftp_u": 0.42, "gopher": 0.44,
    # Remote admin & shell execution (auth-critical)
    "ssh": 0.50, "telnet": 0.70, "login": 0.65, "klogin": 0.66, "kshell": 0.67,
    "shell": 0.68, "exec": 0.69, "rje": 0.63, "remote_job": 0.64, "supdup": 0.62,
    # Messaging & Mail
    "pop_3": 0.75, "pop_2": 0.74, "imap4": 0.73, "courier": 0.72,
    "nntp": 0.76, "nnsp": 0.77, "mtp": 0.78, "IRC": 0.79,
    # Directory, DB, and Windows protocols
    "smb": 0.60, "auth": 0.58, "finger": 0.57, "whois": 0.56,
    "ldap": 0.55, "sql_net": 0.54, "X11": 0.53, "netstat": 0.52,
    "netbios_dgm": 0.47, "netbios_ns": 0.48, "netbios_ssn": 0.49,
    # Routing, system & legacy RPC
    "bgp": 0.81, "sunrpc": 0.83, "systat": 0.84, "iso_tsap": 0.85,
    "uucp": 0.86, "uucp_path": 0.87, "vmnet": 0.88, "Z39_50": 0.89,
    # ICMP / Diagnostic
    "ecr_i": 0.80, "eco_i": 0.82, "tim_i": 0.91, "time": 0.92, "daytime": 0.93,
    "discard": 0.94, "echo": 0.95, "urh_i": 0.96, "urp_i": 0.97, "red_i": 0.98,
    "pm_dump": 0.35, "ntp_u": 0.36,
    # Baseline fallback & general
    "private": 0.85, "other": 0.90, "ctf": 0.91, "efs": 0.92, "harvest": 0.93, "aol": 0.94, "link": 0.95
}
FLAG_MAP: Dict[str, float] = {
    "SF": 0.0,       # Normal SYN/FIN established and closed
    "S1": 0.1,       # Established, not terminated
    "S2": 0.15,      # Established, close attempt by originator
    "S3": 0.2,       # Established, close attempt by responder
    "S0": 0.35,      # Connection attempt seen, no reply (potential scan)
    "REJ": 0.5,      # Connection rejected
    "RSTR": 0.65,    # Reset by responder
    "RSTO": 0.75,    # Connection reset by originator
    "RSTOS0": 0.8,   # Originator sent reset before connection completed
    "SH": 0.9,       # SYN-ACK half open
    "OTH": 1.0,      # Other irregular flag state
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
            scaled = float_val / max_val
            return 0.0 if scaled < 0.0 else (1.0 if scaled > 1.0 else scaled)

        # Rates and binary flags are already naturally in [0.0, 1.0]
        return 0.0 if float_val < 0.0 else (1.0 if float_val > 1.0 else float_val)

    @classmethod
    def extract_vector(cls, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Extracts and normalizes a 41-dimensional feature vector from a raw flow dictionary.
        Returns a 1D NumPy float64 array of shape (41,).
        """
        values = [
            cls.normalize_value(feature_name, flow_dict.get(feature_name, 0.0))
            for feature_name in FEATURE_NAMES
        ]
        return np.array(values, dtype=np.float64)

    @classmethod
    def extract_batch(cls, flow_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extracts and normalizes an N x 41 feature matrix from a list of flow dictionaries.
        Returns a 2D NumPy float64 array of shape (N, 41).
        """
        if not flow_list:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
        return np.vstack([cls.extract_vector(flow) for flow in flow_list])
