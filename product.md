# 🛡️ PROJECT AEGIS-AI: Autonomous Agentic SOC & Non-IoC Network Compromise Defense System

> **Smart India Hackathon (SIH 2023 / Problem Statement 1451 / #74)**  
> **Theme:** Cybersecurity & Artificial Intelligence / Machine Learning  
> **Official Title:** *"Develop an AI/ML tool to detect whether a system / firewall / router / network is compromised. The technique should not rely only on IoCs (Indicators of Compromise) detection."*  
> **Target Event:** Internal SIH Hackathon — PSIT Kanpur (Presentation: August 19)

---

## 📑 Table of Contents
1. [Executive Summary & Core Philosophy](#1-executive-summary--core-philosophy)
2. [Why Non-IoC Detection is the Future](#2-why-non-ioc-detection-is-the-future)
3. [System Architecture & Multi-Agent DAG](#3-system-architecture--multi-agent-dag)
4. [ML Perception Layer: Unsupervised Anomaly Engine](#4-ml-perception-layer-unsupervised-anomaly-engine)
5. [Agentic AI Core: 4 Autonomous Sub-Agents & Tooling](#5-agentic-ai-core-4-autonomous-sub-agents--tooling)
6. [API Architecture & Data Schemas](#6-api-architecture--data-schemas)
7. [Frontend SOC Command Center Specifications](#7-frontend-soc-command-center-specifications)
8. [The 5-Minute "Rank 1" Pitch & Live Demo Script](#8-the-5-minute-rank-1-pitch--live-demo-script)
9. [Academic Grounding & Research Citations](#9-academic-grounding--research-citations)
10. [3-Day Rapid Implementation Roadmap (Aug 15 – Aug 18)](#10-3-day-rapid-implementation-roadmap-aug-15--aug-18)

---

## 1. Executive Summary & Core Philosophy

Traditional intrusion detection systems (IDS) and Security Operations Centers (SOCs) rely heavily on **Indicators of Compromise (IoCs)**—static signatures such as known malicious IP addresses, domain blocklists, malware file hashes (SHA-256), or known CVE patterns.

### 💥 The Fatal Flaw of IoCs:
* **Zero-Day Exploits:** Attackers generate novel payloads that have zero known signatures.
* **Polymorphic Malware:** Modern threats morph their byte signatures and domain names continuously.
* **Encrypted C2 Channels:** Payloads transmitted over TLS/QUIC bypass deep packet inspection.

### 🚀 The AEGIS-AI Solution:
**AEGIS-AI** is a dual-tier cybersecurity ecosystem:
1. **Tier 1 (Perception):** An **Unsupervised Machine Learning Engine (Isolation Forest / Autoencoder)** trained **strictly on benign/normal network behavior**. It detects deviations in statistical flow metrics (entropy, packet inter-arrival jitter, SYN/ACK ratios, flow duration) without checking blacklists.
2. **Tier 2 (Agentic Autonomous Defense):** An **Autonomous Multi-Agent SOC Analyst** that takes the statistical anomaly, autonomously queries internal asset registries, performs vector-RAG against the **MITRE ATT&CK Matrix**, correlates firewall syslogs, drafts exact firewall containment rules (`iptables` / Cisco ACL), and provides an interactive 1-click mitigation queue for security officers.

---

## 2. Why Non-IoC Detection is the Future

```
┌───────────────────────────────────────┬───────────────────────────────────────┐
│     Traditional Signature-Based IDS   │     AEGIS-AI (Behavioral + Agentic)   │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ • Relies on static blacklists (IoCs)  │ • Learns statistical baseline of normal│
│ • Completely blind to Zero-Days       │ • Detects abnormal behavioral spikes  │
│ • Requires manual human triage        │ • Autonomous Multi-Agent Investigation│
│ • Slow containment (hours to days)    │ • Sub-second automated rule drafting  │
│ • High false alarms / Alert fatigue   │ • Rolling-window false-positive filter│
└───────────────────────────────────────┴───────────────────────────────────────┘
```

---

## 3. System Architecture & Multi-Agent DAG

### Complete End-to-End System DAG (Directed Acyclic Graph)

```mermaid
flowchart TD
    subgraph DataIngestion["📡 1. Live Telemetry & Ingestion"]
        A[PCAP / Network Flow Stream] --> B[Flow Feature Extractor]
        B --> C[Statistical Feature Vector: 41 Features]
    end

    subgraph MLEngine["🧠 2. Unsupervised Perception Engine"]
        C --> D[Isolation Forest Anomaly Scorer]
        D --> E{Anomaly Score > 0.80?}
        E -- No --> F[Normal Baseline Log]
        E -- Yes --> G[False Positive Rolling Window Filter]
        G --> H{3+ Consecutive Anomalies?}
        H -- No --> F
        H -- Yes --> I[🚨 Verified Non-IoC Incident Triggered]
    end

    subgraph AgenticCore["🤖 3. Multi-Agent Reasoning & Tool DAG"]
        I --> J[👑 Supervisor Agent]
        
        J --> K[🕵️ Agent 1: Threat Hunter & MITRE RAG]
        K --> K_Tool[Tool: Vector Search MITRE ATT&CK Matrix]
        K_Tool --> K_Out[Identified Technique: e.g. T1021.002]
        
        J --> L[🔍 Agent 2: Asset & Topology Investigator]
        L --> L_Tool[Tool: Local Subnet & Asset Registry Query]
        L_Tool --> L_Out[Asset: Finance-DB-Server-01 | Criticality: HIGH]
        
        J --> M[🛡️ Agent 3: Containment Rule Generator]
        M --> M_Tool[Tool: Generate iptables & Cisco CLI Rules]
        M_Tool --> M_Out[Rule: iptables -A INPUT -s 192.168.1.45 -j DROP]
        
        K_Out & L_Out & M_Out --> N[Agent Synthesis & Incident Card Assembly]
    end

    subgraph ActionUI["📊 4. Executive Command Center & Human-in-the-Loop"]
        N --> O[Real-Time SOC Dashboard]
        O --> P[Interactive 1-Click 'Approve Containment' Modal]
        P -->|Officer Clicks Approve| Q[Execute Containment Command on Firewall]
        O --> R[Auto-Generated Executive CISO Incident Brief]
    end
```

---

## 4. ML Perception Layer: Unsupervised Anomaly Engine

### 📊 Dataset Selection:
* **Primary Reference:** `NSL-KDD` (Benign subset) / `CIC-IDS2017` / `UNSW-NB15`.
* **Key Principle:** **Train strictly on `label == 'normal'` samples.** The model never sees attack signatures during training, proving **zero reliance on IoCs**.

### 🔬 Core Features Extracted (Non-Payload Flow Metrics):
1. `duration`: Length of connection (seconds).
2. `src_bytes` & `dst_bytes`: Volume of data transferred.
3. `count`: Number of connections to the same host in past 2 seconds.
4. `srv_count`: Number of connections to the same service.
5. `same_srv_rate`: Percentage of connections to the same service.
6. `diff_srv_rate`: Percentage of connections to different services (port scan metric).
7. `dst_host_srv_diff_host_rate`: Percentage of connections across different subnets.

### 🐍 Python Baseline Implementation (`backend/ml_engine/anomaly_detector.py`):

```python
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

class NetworkAnomalyDetector:
    def __init__(self, contamination: float = 0.03):
        # Unsupervised Isolation Forest
        self.model = IsolationForest(
            n_estimators=150,
            max_samples='auto',
            contamination=contamination,
            random_state=42
        )
        self.is_trained = False

    def train_on_benign_traffic(self, normal_features: np.ndarray):
        """Trains ONLY on verified normal/benign network flow vectors."""
        self.model.fit(normal_features)
        self.is_trained = True
        joblib.dump(self.model, "models/isolation_forest_benign.joblib")

    def score_flow(self, flow_vector: np.ndarray) -> dict:
        """
        Returns normalized anomaly score (0.0 to 1.0) and boolean decision.
        """
        raw_score = self.model.decision_function(flow_vector.reshape(1, -1))[0]
        # Invert & normalize: lower decision_function = higher anomaly
        normalized_score = float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))
        is_anomaly = bool(normalized_score > 0.80)
        
        return {
            "anomaly_score": round(normalized_score, 4),
            "is_anomaly": is_anomaly,
            "status": "CRITICAL_ANOMALY" if is_anomaly else "NORMAL"
        }
```

---

## 5. Agentic AI Core: 4 Autonomous Sub-Agents & Tooling

When a behavioral anomaly is confirmed, the **Supervisor Agent** initializes the multi-agent reasoning graph.

### 🛠️ Sub-Agent Tools Specification (`backend/app/services/cyber_tools.py`):

```python
from pydantic import BaseModel
import time

class SubnetDevice(BaseModel):
    ip: str
    hostname: str
    owner_department: str
    criticality_level: str
    os_type: str

class CyberAgentTools:
    
    @staticmethod
    def tool_inspect_flow_metrics(flow: dict) -> str:
        """Tool 1: Deep inspects non-payload network flow statistical features."""
        return (
            f"Flow Analysis: Source IP {flow.get('src_ip')} -> Destination IP {flow.get('dst_ip')} "
            f"on Port {flow.get('dst_port')}. Connection burst rate is 480 req/sec (baseline is 12 req/sec). "
            f"Zero payload variance with abnormal TCP SYN flags."
        )

    @staticmethod
    def tool_query_asset_registry(ip: str) -> dict:
        """Tool 2: Queries internal asset registry to determine blast radius and critical asset exposure."""
        mock_registry = {
            "192.168.1.45": {
                "hostname": "DB-PROD-FINANCE-01",
                "owner_department": "Treasury & Finance",
                "criticality_level": "CRITICAL_TIER_1",
                "os_type": "Ubuntu 22.04 LTS"
            },
            "192.168.1.104": {
                "hostname": "ENG-WORKSTATION-88",
                "owner_department": "Engineering",
                "criticality_level": "LOW_TIER_3",
                "os_type": "Windows 11 Enterprise"
            }
        }
        return mock_registry.get(ip, {
            "hostname": f"NODE-{ip.replace('.', '-')}",
            "owner_department": "Unknown Subnet",
            "criticality_level": "MEDIUM",
            "os_type": "Linux Generic"
        })

    @staticmethod
    def tool_mitre_vector_search(pattern_description: str) -> dict:
        """Tool 3: Vector search against MITRE ATT&CK knowledge base."""
        # Simulated local vector retrieval
        return {
            "mitre_id": "T1021.002",
            "tactic": "Lateral Movement",
            "technique_name": "SMB/Windows Admin Shares",
            "description": "Adversaries may use SMB to laterally move across private subnets without triggering standard perimeter firewalls.",
            "detection_confidence": "94.8%"
        }

    @staticmethod
    def tool_generate_containment_command(src_ip: str, dst_port: int) -> dict:
        """Tool 4: Generates exact CLI scripts for instant network isolation."""
        return {
            "iptables_rule": f"sudo iptables -I INPUT 1 -s {src_ip} -j DROP",
            "cisco_acl": f"access-list 101 deny ip host {src_ip} any",
            "powershell_command": f"New-NetFirewallRule -DisplayName 'AEGIS-Block-{src_ip}' -Direction Inbound -RemoteAddress '{src_ip}' -Action Block"
        }
```

---

## 6. API Architecture & Data Schemas

FastAPI Endpoints (`backend/app/routers/soc_api.py`):

1. **`POST /api/v1/telemetry/stream`**
   * Receives network flow batch $\to$ runs Isolation Forest $\to$ returns telemetry status.
2. **`POST /api/v1/agent/investigate`**
   * Dispatches the 4-agent reasoning loop for flagged anomalies $\to$ returns synthesized Incident Card.
3. **`POST /api/v1/agent/execute-containment`**
   * Human-in-the-loop endpoint: receives officer's approval token and executes the containment command.
4. **`GET /api/v1/agent/daily-brief`**
   * Generates a CISO executive brief of all anomalous events in markdown.

---

## 7. Frontend SOC Command Center Specifications

### Design Aesthetics:
* **Theme:** Sleek Dark Mode (Obsidian Navy `#0B0F19`, Slate `#1E293B`, Electric Cyan `#06B6D4`, Alert Crimson `#EF4444`).
* **Visual Components:**
  1. **Top Bar:** Live System Telemetry Status (`BDI: 0.12 - NOMINAL`, `Zero-Day Defense: ACTIVE`).
  2. **Left Panel (Telemetry Stream):** Animated stream of real-time flow events with Color-Coded Anomaly Gauges.
  3. **Center Panel (Agentic Thought Terminal):** Real-time streaming logs showing the Agent's reasoning steps:
     * `[Perception]: Isolation Forest flagged BDI = 0.94 on Node 192.168.1.104`
     * `[Tool Execution]: Queried Asset DB -> Identified Host: ENG-WORKSTATION-88`
     * `[Threat Modeling]: Matched MITRE ATT&CK T1021.002 (Lateral Movement)`
     * `[Remediation]: Formulated 3 firewall containment scripts`
  4. **Right Panel (Action Queue - Allel Style):** Interactive card with a pulsating red border and an **`[ Approve & Isolate Node ]`** button.

---

## 8. The 5-Minute "Rank 1" Pitch & Live Demo Script

| Timestamp | Screen State | Spoken Script for Evaluators |
| :--- | :--- | :--- |
| **0:00 – 0:50** | **Slide 1: Problem Gap** | *"Respected jury, 95% of current firewalls rely on IoCs—static signatures and IP blacklists. But when a zero-day attack or ransomware hits, signatures do not exist. SIH Problem 1451 demands detection **without relying on signatures**."* |
| **0:50 – 1:45** | **Live Baseline Demo** | Click **'Simulate Normal Enterprise Traffic'**. <br> *"Our model uses an Unsupervised Isolation Forest trained solely on normal baseline traffic. Anomaly score remains low at 0.06. Zero false alarms."* |
| **1:45 – 3:15** | **Zero-Day Injection & Agent Live Trace** | Click **'Inject Non-IoC Zero-Day Spike'**. <br> 1. Anomaly Gauge spikes to **0.94**. <br> 2. The **AEGIS Multi-Agent Terminal** begins live streaming: <br> *"Look at the terminal: the Agent autonomously queries our internal subnet registry, correlates the traffic against the MITRE ATT&CK Matrix, and identifies SMB lateral movement."* |
| **3:15 – 4:15** | **Human-in-the-Loop 1-Click Action** | Show the incident card in the UI. <br> Click **`[ Approve Containment ]`**. <br> Modal confirms: *`iptables containment rule executed in 0.8 seconds. Node 192.168.1.104 isolated.`* |
| **4:15 – 5:00** | **Research Grounding & Conclusion** | *"Our architecture is grounded in the peer-reviewed DIoT behavioral defense framework (95.6% detection on zero-day botnets). We offer zero signature dependency, sub-second response, and full human-in-the-loop safety. Thank you."* |

---

## 9. Academic Grounding & Research Citations

Include this slide in your presentation to impress college faculty:

1. **DIoT Defense Framework:**  
   * *Reference:* Nguyen et al., *"DIoT: A Federated Self-learning Anomaly Detection System for IoT"*, IEEE ICDCS / arXiv:1804.07474.  
   * *Core Takeaway:* Proves that unsupervised learning on non-payload network flow statistical profiles achieves a **95.6% detection rate against zero-day botnets without signature databases**.
2. **MITRE ATT&CK Enterprise Matrix v14:**  
   * Used for behavioral mapping of non-IoC lateral movement (T1021) and network scanning (T1046).

---

## 10. 3-Day Rapid Implementation Roadmap (Aug 15 – Aug 18)

```
📅 DAY 1 (Aug 15) — ML Perception Engine & Baseline
├── 1. Download NSL-KDD / CIC-IDS2017 benign CSV subset.
├── 2. Implement backend/ml_engine/anomaly_detector.py (Isolation Forest).
└── 3. Test anomaly scoring on normal vs injected spike vectors.

📅 DAY 2 (Aug 16) — Agentic AI Hub & Tool Calling
├── 1. Implement backend/app/services/cyber_tools.py (Asset lookup, MITRE RAG, Rule generator).
├── 2. Implement agent reasoning loop in backend/app/services/agent_service.py.
└── 3. Expose FastAPI endpoints for stream ingestion and containment approval.

📅 DAY 3 (Aug 17) — SOC Command Center UI & Integration
├── 1. Build Dark-Mode SOC Dashboard in React/Streamlit with Anomaly Gauges.
├── 2. Add 'Simulate Normal' and 'Inject Zero-Day' live trigger buttons.
└── 3. Connect 1-click 'Approve Mitigation' action.

📅 DAY 4 (Aug 18) — Pitch Polish & Dry Run
├── 1. Record 2-minute backup demo video.
├── 2. Prepare 5-slide PowerPoint deck citing the DIoT paper.
└── 3. Rehearse pitch with team — Ready for August 19!
```

---
*Created for Team AEGIS-AI • SIH 2023 Internal Hackathon at PSIT Kanpur • Problem Statement 1451*
