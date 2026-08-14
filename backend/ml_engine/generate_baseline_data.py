"""
Dataset and Baseline Generator for Project AEGIS-AI.
Generates:
1. backend/data/benign_baseline.csv: 100% normal flow records (NSL-KDD inspired)
2. backend/data/synthetic_attack_samples.json: Zero-day stealth attacks (T1021, T1046, T1071, T1048)
3. backend/data/asset_inventory.json: Enterprise subnet topology & asset registry
4. backend/data/mitre_attack_kb.json: Local MITRE ATT&CK taxonomy for agent RAG
"""

import json
import os
import random
import numpy as np
import pandas as pd
from backend.ml_engine.feature_extractor import FEATURE_NAMES, FlowFeatureExtractor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

def generate_benign_baseline(n_samples: int = 5000) -> str:
    """Generates pure normal/benign network traffic records."""
    random.seed(42)
    rng = np.random.default_rng(42)
    
    records = []
    services = ["http", "dns", "smtp", "ssh", "other"]
    service_weights = [0.60, 0.20, 0.10, 0.08, 0.02]
    
    for _ in range(n_samples):
        srv = random.choices(services, weights=service_weights)[0]
        
        # Realistic benign distributions
        if srv == "http":
            duration = rng.exponential(scale=2.0)
            src_bytes = int(rng.lognormal(mean=5.8, sigma=0.35))
            dst_bytes = int(rng.exponential(scale=3500))
            flag = "SF"
            protocol = "tcp"
        elif srv == "dns":
            duration = rng.exponential(scale=0.05)
            src_bytes = int(rng.lognormal(mean=4.17, sigma=0.22))
            dst_bytes = int(rng.lognormal(mean=4.94, sigma=0.27))
            flag = "SF"
            protocol = "udp"
        elif srv == "smtp":
            duration = rng.exponential(scale=4.0)
            src_bytes = int(rng.lognormal(mean=6.68, sigma=0.30))
            dst_bytes = int(rng.lognormal(mean=7.09, sigma=0.32))
            flag = "SF"
            protocol = "tcp"
        elif srv == "ssh":
            duration = rng.exponential(scale=60.0)
            src_bytes = int(rng.lognormal(mean=7.82, sigma=0.31))
            dst_bytes = int(rng.lognormal(mean=8.29, sigma=0.29))
            flag = "SF"
            protocol = "tcp"
        else:
            duration = rng.exponential(scale=1.0)
            src_bytes = int(rng.lognormal(mean=5.30, sigma=0.38))
            dst_bytes = int(rng.lognormal(mean=5.30, sigma=0.38))
            flag = random.choice(["SF", "SF", "SF", "REJ"])
            protocol = "tcp"
            
        record = {
            "duration": float(round(max(0.0, duration), 3)),
            "protocol_type": protocol,
            "service": srv,
            "flag": flag,
            "src_bytes": max(1, src_bytes),
            "dst_bytes": max(1, dst_bytes),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": int(rng.choice([0, 1], p=[0.98, 0.02])),
            "num_failed_logins": 0,
            "logged_in": 1 if srv in ["http", "ssh", "smtp"] else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": int(max(1, rng.poisson(lam=4))),
            "srv_count": int(max(1, rng.poisson(lam=3))),
            "serror_rate": float(round(rng.beta(0.1, 10), 3)),
            "srv_serror_rate": float(round(rng.beta(0.1, 10), 3)),
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": float(round(rng.uniform(0.85, 1.0), 3)),
            "diff_srv_rate": float(round(rng.uniform(0.0, 0.15), 3)),
            "srv_diff_host_rate": float(round(rng.uniform(0.0, 0.10), 3)),
            "dst_host_count": int(rng.integers(10, 255)),
            "dst_host_srv_count": int(rng.integers(10, 255)),
            "dst_host_same_srv_rate": float(round(rng.uniform(0.80, 1.0), 3)),
            "dst_host_diff_srv_rate": float(round(rng.uniform(0.0, 0.20), 3)),
            "dst_host_same_src_port_rate": float(round(rng.uniform(0.0, 0.15), 3)),
            "dst_host_srv_diff_host_rate": float(round(rng.uniform(0.0, 0.10), 3)),
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
            "label": "normal",
        }
        records.append(record)
        
    df = pd.DataFrame(records)
    csv_path = os.path.join(DATA_DIR, "benign_baseline.csv")
    df.to_csv(csv_path, index=False)
    print(f"[+] Benign baseline generated: {len(df)} records -> {csv_path}")
    return csv_path


def generate_synthetic_attacks() -> str:
    """Generates ground-truth zero-day attack flow samples for non-IoC validation."""
    attacks = [
        {
            "attack_id": "ATK-ZERO-001",
            "name": "Stealthy SMB Lateral Movement",
            "mitre_id": "T1021.002",
            "description": "Internal subnet burst targeting port 445 with zero payload variance and high diff_host_rate.",
            "flow_data": {
                "duration": 0.12,
                "protocol_type": "tcp",
                "service": "smb",
                "flag": "SF",
                "src_bytes": 48200,
                "dst_bytes": 120,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 4,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 2,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 3,
                "num_shells": 0,
                "num_access_files": 2,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 480,
                "srv_count": 450,
                "serror_rate": 0.02,
                "srv_serror_rate": 0.01,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 0.98,
                "diff_srv_rate": 0.02,
                "srv_diff_host_rate": 0.88,
                "dst_host_count": 255,
                "dst_host_srv_count": 240,
                "dst_host_same_srv_rate": 0.95,
                "dst_host_diff_srv_rate": 0.05,
                "dst_host_same_src_port_rate": 0.82,
                "dst_host_srv_diff_host_rate": 0.91,
                "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0,
                "src_ip": "192.168.1.104",
                "dst_ip": "192.168.1.45",
                "src_port": 51234,
                "dst_port": 445,
            }
        },
        {
            "attack_id": "ATK-ZERO-002",
            "name": "SYN Port Sweep & Subnet Reconnaissance",
            "mitre_id": "T1046",
            "description": "High diff_srv_rate and S0 half-open connections across wide port range.",
            "flow_data": {
                "duration": 0.01,
                "protocol_type": "tcp",
                "service": "other",
                "flag": "S0",
                "src_bytes": 0,
                "dst_bytes": 0,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 0,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 510,
                "srv_count": 12,
                "serror_rate": 0.98,
                "srv_serror_rate": 0.95,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 0.02,
                "diff_srv_rate": 0.98,
                "srv_diff_host_rate": 0.75,
                "dst_host_count": 255,
                "dst_host_srv_count": 10,
                "dst_host_same_srv_rate": 0.04,
                "dst_host_diff_srv_rate": 0.96,
                "dst_host_same_src_port_rate": 0.92,
                "dst_host_srv_diff_host_rate": 0.85,
                "dst_host_serror_rate": 0.98,
                "dst_host_srv_serror_rate": 0.96,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0,
                "src_ip": "10.0.4.15",
                "dst_ip": "192.168.1.1",
                "src_port": 44123,
                "dst_port": 80,
            }
        },
        {
            "attack_id": "ATK-ZERO-003",
            "name": "Encrypted C2 Beaconing Channel",
            "mitre_id": "T1071.001",
            "description": "Strictly periodic low-latency heartbeats with rigid byte symmetry over HTTPS.",
            "flow_data": {
                "duration": 0.45,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 128,
                "dst_bytes": 128,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 15,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 5,
                "root_shell": 1,
                "su_attempted": 1,
                "num_root": 5,
                "num_file_creations": 4,
                "num_shells": 2,
                "num_access_files": 4,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 480,
                "srv_count": 480,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 1,
                "dst_host_srv_count": 1,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 1.0,
                "dst_host_srv_diff_host_rate": 0.0,
                "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0,
                "src_ip": "192.168.1.72",
                "dst_ip": "198.51.100.22",
                "src_port": 58912,
                "dst_port": 443,
            }
        }
    ]
    
    out_path = os.path.join(DATA_DIR, "synthetic_attack_samples.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(attacks, f, indent=2)
    print(f"[+] Synthetic attack samples generated: {len(attacks)} attacks -> {out_path}")
    return out_path


def generate_asset_inventory() -> str:
    """Generates mock enterprise asset inventory & criticality registry."""
    assets = {
        "192.168.1.45": {
            "ip": "192.168.1.45",
            "hostname": "DB-PROD-FINANCE-01",
            "owner_department": "Treasury & Core Banking",
            "criticality_level": "CRITICAL_TIER_1",
            "os_type": "Ubuntu 22.04 LTS (PostgreSQL 15)",
            "mac_address": "00:50:56:A1:B2:C3",
            "subnet": "192.168.1.0/24 (Production Core DB Subnet)",
            "crown_jewel": True
        },
        "192.168.1.10": {
            "ip": "192.168.1.10",
            "hostname": "DC-PRIMARY-AD01",
            "owner_department": "IT Operations & Identity",
            "criticality_level": "CRITICAL_TIER_1",
            "os_type": "Windows Server 2022 (Active Directory)",
            "mac_address": "00:50:56:B2:C3:D4",
            "subnet": "192.168.1.0/24 (Production Core Services)",
            "crown_jewel": True
        },
        "192.168.1.104": {
            "ip": "192.168.1.104",
            "hostname": "ENG-WORKSTATION-88",
            "owner_department": "Engineering Development",
            "criticality_level": "LOW_TIER_3",
            "os_type": "Windows 11 Enterprise",
            "mac_address": "00:50:56:C3:D4:E5",
            "subnet": "192.168.1.0/24 (Corporate LAN)",
            "crown_jewel": False
        },
        "192.168.1.72": {
            "ip": "192.168.1.72",
            "hostname": "SALES-LAPTOP-14",
            "owner_department": "Sales & Marketing",
            "criticality_level": "MEDIUM",
            "os_type": "macOS Sonoma",
            "mac_address": "00:50:56:D4:E5:F6",
            "subnet": "192.168.1.0/24 (Corporate LAN)",
            "crown_jewel": False
        },
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "GATEWAY-FIREWALL-01",
            "owner_department": "Network Security",
            "criticality_level": "CRITICAL_TIER_1",
            "os_type": "pfSense Enterprise Router",
            "mac_address": "00:50:56:00:00:01",
            "subnet": "192.168.1.0/24 (Perimeter Gateway)",
            "crown_jewel": True
        }
    }
    
    out_path = os.path.join(DATA_DIR, "asset_inventory.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=2)
    print(f"[+] Enterprise asset inventory generated: {len(assets)} nodes -> {out_path}")
    return out_path


def generate_mitre_knowledge_base() -> str:
    """Generates local MITRE ATT&CK taxonomy for offline semantic vector search."""
    kb = [
        {
            "technique_id": "T1021.002",
            "tactic": "Lateral Movement",
            "technique_name": "SMB/Windows Admin Shares",
            "description": "Adversaries may use valid accounts to interact with remote SMB services over Port 445 to laterally traverse internal enterprise subnets.",
            "indicators": ["port 445 burst", "same srv rate high", "cross subnet traversal", "smb file creation"],
            "mitigation": "Disable SMBv1, enforce SMB signing, block Port 445 between workstations, isolate compromised internal host.",
            "recommended_firewall_action": "DROP_SRC_IP"
        },
        {
            "technique_id": "T1046",
            "tactic": "Reconnaissance",
            "technique_name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts across the network using port sweeps or SYN scanning.",
            "indicators": ["high diff_srv_rate", "S0 flags", "half open syn", "rapid multi-port probe"],
            "mitigation": "Configure firewall rate-limiting, drop unsolicited SYN half-open packets, isolate scanning source.",
            "recommended_firewall_action": "DROP_SRC_IP"
        },
        {
            "technique_id": "T1071.001",
            "tactic": "Command and Control",
            "technique_name": "Web Protocols (HTTP/HTTPS Beaconing)",
            "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to bypass network security monitoring with periodic beacon intervals.",
            "indicators": ["periodic low-jitter beacon", "equal byte symmetry", "low duration repeat bursts"],
            "mitigation": "Inspect TLS handshake headers, apply egress DNS filtering, block C2 destination IP.",
            "recommended_firewall_action": "DROP_DST_IP"
        },
        {
            "technique_id": "T1048",
            "tactic": "Exfiltration",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "description": "Adversaries may steal data by exfiltrating it over a different protocol than the command and control channel (e.g. DNS tunneling or raw UDP bursts).",
            "indicators": ["extreme src_bytes to dst_bytes ratio", "abnormal udp duration", "high entropy outbound payload"],
            "mitigation": "Block unauthorized egress protocols, enforce strict DNS inspection and rate limiting.",
            "recommended_firewall_action": "DROP_SRC_IP"
        }
    ]
    
    out_path = os.path.join(DATA_DIR, "mitre_attack_kb.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=2)
    print(f"[+] MITRE ATT&CK Knowledge Base generated: {len(kb)} techniques -> {out_path}")
    return out_path


if __name__ == "__main__":
    generate_benign_baseline()
    generate_synthetic_attacks()
    generate_asset_inventory()
    generate_mitre_knowledge_base()
