# 📋 PROJECT AEGIS-AI: System & Technical Requirements Specification

> **Document Code:** `AEGIS-REQ-001`  
> **Target Version:** v1.0.0 (Core MVP) & v2.0.0 (Enterprise)  
> **Classification:** Technical Requirements Specification

---

## 1. Functional Requirements (FR)

### FR-01: Live Telemetry Stream Ingestion
* **Description:** The system must ingest high-velocity network flow vectors in real time over HTTP/REST and WebSockets.
* **Inputs:** JSON payload containing flow records with statistical fields (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `duration`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, `same_srv_rate`, `diff_srv_rate`, `dst_host_srv_diff_host_rate`, etc.).
* **Processing:** Validate schema with Pydantic, convert raw metrics to normalized NumPy feature vectors ($N \times 41$), and push to in-memory processing buffer.
* **Output:** HTTP `200 OK` with ingestion receipt or WebSocket broadcast stream event.
* **Acceptance Criteria:** Must process $\ge 1,000$ flow records/second with ingestion latency $< 10\text{ ms}$.

### FR-02: Non-IoC Unsupervised Anomaly Perception
* **Description:** The system must compute an anomaly score strictly using behavioral deviation metrics without consulting signature databases or IP blacklists.
* **Inputs:** Normalized feature vector $\mathbf{x} \in \mathbb{R}^{41}$.
* **Processing:** 
  1. Compute raw decision function using pre-trained `IsolationForest` (trained strictly on benign baseline).
  2. Normalize score to range $[0.00, 1.00]$ using inverted offset transformation: $\text{BDI} = \text{clip}(1.0 - (\text{raw\_score} + 0.5), 0.0, 1.0)$.
  3. Classify vector as anomaly if $\text{BDI} \ge 0.80$.
* **Output:** Anomaly evaluation object containing `anomaly_score`, `is_anomaly`, `bdi_status`, and `confidence_score`.
* **Acceptance Criteria:** Score calculated in $< 5\text{ ms}$ per vector; zero signature lookups performed.

### FR-03: Rolling-Window False-Positive Filter
* **Description:** The system must eliminate transient network noise/spikes before escalating alerts to the agentic core.
* **Inputs:** Stream of sequential anomaly flags per source IP.
* **Processing:** Maintain a sliding time-window queue (e.g., last 5 seconds or $K=3$ consecutive anomaly ticks). Escalate only when sustained anomalous deviation is confirmed.
* **Output:** Boolean `trigger_agentic_investigation`.
* **Acceptance Criteria:** Single isolated spikes (e.g., normal large file download) must be filtered without waking the agent core.

### FR-04: Multi-Agent Triage & Investigation Dispatch
* **Description:** The system must autonomously initialize a 4-agent reasoning Directed Acyclic Graph (DAG) upon verified anomaly.
* **Agents:**
  1. **Supervisor Agent:** Coordinates investigation, delegates sub-tasks, and synthesizes final incident card.
  2. **Threat Hunter Agent:** Analyzes flow statistical characteristics (SYN burst, low payload variance, multi-port probe) and queries vector database to map MITRE ATT&CK Tactics/Techniques.
  3. **Asset & Topology Investigator Agent:** Queries internal subnet asset registry to determine hostname, department, operating system, and criticality level (e.g., `CRITICAL_TIER_1` vs `LOW_TIER_3`).
  4. **Containment Rule Generator Agent:** Synthesizes platform-specific firewall commands (`iptables`, Cisco ACL, Windows PowerShell).
* **Output:** Unified JSON Incident Card with explainable reasoning trace.
* **Acceptance Criteria:** Complete multi-agent DAG execution completes in $< 1,500\text{ ms}$.

### FR-05: Real-Time Agent Thought Streaming
* **Description:** The system must stream intermediate agent reasoning thoughts, tool calls, and tool outputs to the frontend in real time.
* **Protocol:** WebSockets (`ws://localhost:8000/api/v1/ws/agent-thoughts`) or Server-Sent Events (SSE).
* **Format:** Streamed JSON events containing `agent_name`, `step_type` (`THOUGHT` | `TOOL_CALL` | `TOOL_OUTPUT` | `SYNTHESIS`), `message`, and `timestamp`.
* **Acceptance Criteria:** Time from agent execution step to UI display $< 50\text{ ms}$.

### FR-06: Human-in-the-Loop (HITL) Containment Approval
* **Description:** The system must require human authorization before executing any network isolation command on firewalls or routers.
* **Inputs:** HTTP `POST /api/v1/agent/execute-containment` with `incident_id`, `officer_token`, `rule_type`, and `approval_action`.
* **Processing:** Verify cryptographic authorization token, execute designated firewall containment rule (or invoke mock driver in demo mode), and record audit entry.
* **Output:** Status report: `CONTAINMENT_ACTIVE`, execution time, and affected host status.
* **Acceptance Criteria:** Rule deployed in $< 800\text{ ms}$ upon officer click.

### FR-07: Executive CISO Incident Brief Generation
* **Description:** The system must automatically generate structured executive incident briefs in GitHub-flavored Markdown.
* **Content:** Incident ID, Timestamp, Compromised Asset, Blast Radius, MITRE Technique ID, Behavioral Metrics, Containment Action Taken, and Recommended Post-Incident Hardening Steps.
* **Acceptance Criteria:** Instantaneous retrieval via `GET /api/v1/agent/daily-brief`.

### FR-08: Interactive Telemetry Simulation Sandbox
* **Description:** The system must provide interactive triggers to simulate both benign normal enterprise baseline traffic and non-IoC zero-day attack traffic for demonstration and evaluation.
* **Triggers:**
  - `POST /api/v1/telemetry/simulate/normal` (Replays baseline flow records; BDI stays $\le 0.15$).
  - `POST /api/v1/telemetry/simulate/attack` (Injects stealthy SMB lateral movement or SYN burst; BDI spikes to $\ge 0.90$).

---

## 2. Non-Functional Requirements (NFR)

### NFR-01: Performance & Latency
| Metric | Threshold Target |
| :--- | :--- |
| Telemetry Ingestion Latency | $< 10\text{ ms}$ per batch |
| Anomaly Inference Latency | $< 5\text{ ms}$ per vector |
| Multi-Agent DAG Total Execution | $< 1,500\text{ ms}$ |
| WebSocket Frame Delivery | $< 50\text{ ms}$ end-to-end |
| UI Frame Rate | Stable 60 FPS under continuous telemetry stream |

### NFR-02: Security & Zero-Trust
* **Zero Payload Inspection:** The system must never inspect or log cleartext user payloads, adhering to zero-trust privacy and encryption preservation (TLS 1.3/QUIC compliant).
* **Cryptographic Action Tokens:** All containment requests must include valid operator tokens to prevent unauthorized automated lockouts.
* **Tamper-Evident Audit Trail:** All incident resolutions and firewall executions must be logged with SHA-256 hash chaining.

### NFR-03: Scalability & Resource Efficiency
* **ML Inference Memory Footprint:** Isolation Forest model memory $< 150\text{ MB}$.
* **Backend Resource Consumption:** $< 512\text{ MB}$ RAM on standard edge nodes or standard hardware during live evaluation.
* **Concurrency:** Capable of sustaining 10 concurrent WebSocket dashboard connections simultaneously.

### NFR-04: Reliability & Fault Tolerance
* If an external LLM/vector service is temporarily unavailable, the system must gracefully fall back to local rule-based heuristic threat modeling without crashing the telemetry stream.
* If a containment command fails, the system must retry once and alert the operator with exact error details.

### NFR-05: Usability & Aesthetics
* Interface must use high-contrast dark cybersecurity visual design tokens (Obsidian Navy `#0B0F19`, Electric Cyan `#06B6D4`, Crimson Alert `#EF4444`).
* Dashboard must be responsive and functional across resolutions ($1920\times 1080$ down to $1366\times 768$).
* Zero lag or UI freezing during active telemetry streaming.

---

## 3. Data & Feature Engineering Specifications

### 3.1 Feature Vector Taxonomy (41 Flow Dimensions)
The system uses statistical features modeled after the standard NSL-KDD and CIC-IDS2017 flow taxonomies:

```
┌─────────────────────────┬─────────────────────────────────────────────────────────────┐
│ Category                │ Key Statistical Features (Non-Payload)                      │
├─────────────────────────┼─────────────────────────────────────────────────────────────┤
│ Basic Flow Metrics      │ duration, protocol_type, service, flag, src_bytes, dst_bytes │
│ Content-Agnostic Flow   │ land, wrong_fragment, urgent, num_failed_logins, logged_in │
│ Time-Window Traffic     │ count, srv_count, serror_rate, srv_serror_rate, rerror_rate│
│ Host-Based Traffic      │ same_srv_rate, diff_srv_rate, srv_diff_host_rate            │
│ Destination Host Stats  │ dst_host_count, dst_host_srv_count, dst_host_same_srv_rate │
│ Dispersal & Jitter      │ dst_host_diff_srv_rate, dst_host_srv_diff_host_rate         │
└─────────────────────────┴─────────────────────────────────────────────────────────────┘
```

### 3.2 Feature Preprocessing Pipeline
1. **Categorical Encoding:** One-Hot Encoding or Ordinal Mapping for `protocol_type` (TCP, UDP, ICMP) and `service` (HTTP, SMB, DNS, SSH).
2. **MinMax / Robust Scaler:** Numeric continuous features normalized to $[0.0, 1.0]$.
3. **Imputation:** Zero-fill for missing or out-of-bounds telemetry records.

---

## 4. Software & Hardware Stack Requirements

### 4.1 Backend Stack
* **Language:** Python 3.10+ / 3.11
* **Web Framework:** FastAPI (Asynchronous, High-Performance, OpenAPI Documentation)
* **Server:** Uvicorn (ASGI Server)
* **ML / Data Science:** Scikit-learn (`IsolationForest`), NumPy, Pandas, Joblib
* **Agentic Orchestration:** Custom Lightweight Async DAG Orchestrator / LangGraph / LangChain Core
* **Vector Store (Local):** ChromaDB / FAISS (Embedded in-memory vector database for MITRE ATT&CK embeddings)
* **Data Validation:** Pydantic v2

### 4.2 Frontend Stack
* **Core:** HTML5, Modern Vanilla JavaScript (ES6+) or React/Vite
* **Styling:** Custom Vanilla CSS with Design Tokens & CSS Variables (Obsidian Dark Theme)
* **Charts & Gauges:** Chart.js / Canvas-based real-time anomaly telemetry gauge
* **Realtime Protocol:** Native WebSocket API (`ws://`)

### 4.3 Hardware Requirements
* **Minimum Dev/Demo Environment:** 4-Core CPU, 8 GB RAM, 2 GB disk space.
* **Operating Systems Supported:** macOS (Apple Silicon & Intel), Linux (Ubuntu 20.04/22.04 LTS), Windows 11 (WSL2).
