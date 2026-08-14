# 📜 PROJECT AEGIS-AI: Development Rules, Architecture Invariants & Agent Guidelines

> **Document Code:** `AEGIS-RULES-001`  
> **Target Version:** v1.0.0  
> **Scope:** Engineering Standards, Architectural Invariants, AI Prompt Templates & Safety Guardrails

---

## 1. Non-Negotiable Architectural Invariants

### 🛑 Rule 1: Zero IoC Dependency in Perception Tier
* **Rule:** The ML Perception Engine (`backend/ml_engine/`) must **NEVER** use static IP blocklists, domain blacklists, CVE signature tables, or SHA-256 file hashes to classify network traffic.
* **Rationale:** SIH Problem 1451 strictly tests non-IoC detection capability against zero-day compromises and polymorphic threats.
* **Enforcement:** All anomaly detection must be computed strictly through statistical flow features (entropy, packet inter-arrival jitter, SYN/ACK ratios, flow duration, byte variance).

### 🛑 Rule 2: Unsupervised Benign-Only Training
* **Rule:** Machine learning models (Isolation Forest / Autoencoder) must be trained **EXCLUSIVELY** on verified normal/benign network traffic records (`label == 'normal'`).
* **Rationale:** The model learns what "normal baseline enterprise behavior" looks like. Any deviation is flagged by high reconstruction loss or isolation depth without ever having seen the attack signature during training.

### 🛑 Rule 3: Human-in-the-Loop (HITL) Safety Gate
* **Rule:** The Agentic Core must **NEVER** execute live firewall isolation commands autonomously without an explicit human authorization token from the SOC analyst.
* **Rationale:** Autonomous firewall isolation carries operational risk (false lockouts of critical production services).
* **Enforcement:** Agent generates containment scripts and presents them in the UI Action Queue. Execution requires a signed `POST /api/v1/agent/execute-containment` call from the operator.

### 🛑 Rule 4: Deterministic Pydantic Tool Schemas
* **Rule:** All agent tools (`backend/app/services/cyber_tools.py`) must have strict Pydantic v2 input and output schemas. Agents must not invoke arbitrary bash subshells without schema-validated parameters.
* **Rationale:** Prevents prompt injection, hallucinations, and malformed command generation.

### 🛑 Rule 5: Sub-Second Streaming Transparency
* **Rule:** Agent reasoning steps and intermediate tool outputs must be streamed to the client via WebSockets or Server-Sent Events (SSE) within $< 50\text{ ms}$ of generation.
* **Rationale:** Provides full explainability for evaluators and eliminates "black box" AI concerns.

---

## 2. Directory Structure & Separation of Concerns

The project follows a Clean Architecture structure:

```
sih/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application entrypoint
│   │   ├── core/
│   │   │   ├── config.py               # Application settings & environment vars
│   │   │   ├── security.py             # Auth tokens & audit log hashing
│   │   │   └── websocket_manager.py    # Real-time WebSocket connection hub
│   │   ├── models/
│   │   │   ├── telemetry.py            # Flow schemas & feature vector models
│   │   │   ├── incident.py             # Incident cards, BDI status, MITRE models
│   │   │   └── containment.py          # Firewall rule schemas & approval tokens
│   │   ├── routers/
│   │   │   ├── telemetry_router.py     # /api/v1/telemetry (ingest & simulate)
│   │   │   ├── agent_router.py         # /api/v1/agent (investigate & daily-brief)
│   │   │   ├── containment_router.py   # /api/v1/agent/execute-containment
│   │   │   └── ws_router.py            # /api/v1/ws (real-time stream)
│   │   └── services/
│   │       ├── agent_supervisor.py     # Multi-Agent DAG Orchestrator
│   │       ├── threat_hunter_agent.py  # MITRE ATT&CK vector search agent
│   │       ├── asset_agent.py          # Subnet topology & criticality lookup
│   │       ├── rule_generator_agent.py # iptables / Cisco ACL / PowerShell compiler
│   │       └── cyber_tools.py          # Deterministic Python tools for agents
│   ├── ml_engine/
│   │   ├── anomaly_detector.py         # Isolation Forest & Autoencoder engine
│   │   ├── feature_extractor.py        # 41-feature extraction & normalization
│   │   ├── rolling_filter.py           # False-positive rolling window filter
│   │   └── train_model.py              # Script to train model on benign data
│   ├── data/
│   │   ├── benign_baseline.csv         # Normal flow training records
│   │   ├── mitre_attack_kb.json        # Local MITRE ATT&CK v14 taxonomy
│   │   └── asset_inventory.json        # Enterprise subnet asset registry
│   └── models_saved/
│       └── isolation_forest_benign.joblib # Serialized model artifact
├── frontend/
│   ├── index.html                      # SOC Command Center dashboard
│   ├── css/
│   │   ├── variables.css               # Design tokens & color variables
│   │   ├── layout.css                  # Grid layout & responsive panels
│   │   └── components.css              # Gauges, cards, terminal styling
│   └── js/
│       ├── app.js                      # Main UI controller & WebSocket client
│       ├── telemetry_gauge.js          # Canvas-based BDI Anomaly Meter
│       ├── terminal_stream.js          # Real-time Agent Thought Terminal
│       └── incident_modal.js           # 1-Click Containment Action Modal
├── tests/
│   ├── test_anomaly_detector.py        # ML scoring tests (normal vs anomaly)
│   ├── test_agent_dag.py               # Multi-agent tool execution tests
│   └── test_telemetry_api.py           # FastAPI endpoint integration tests
├── prd.md
├── requirement.md
├── rules.md
├── phases.md
├── design.md
├── memory.md
└── product.md
```

---

## 3. Code Style & Standards

### 3.1 Python Backend Guidelines
* **Type Annotations:** 100% of function signatures, arguments, and return types must be fully type-hinted using standard Python typing (`typing.Dict`, `typing.List`, `typing.Optional`, Pydantic models).
* **Async by Default:** All FastAPI route handlers, WebSocket managers, and agent tool execution calls must be `async def`.
* **Docstrings:** Use Google-style docstrings for all classes and functions.
* **Error Handling:** Never use bare `except:`. Always catch specific exceptions (`ValueError`, `HTTPException`, `KeyError`) and return structured error responses with HTTP status codes.

```python
# GOOD EXAMPLE:
async def score_telemetry_vector(vector: List[float]) -> AnomalyResult:
    """Scores a 41-feature network telemetry vector against the benign baseline.
    
    Args:
        vector: List of 41 normalized float values representing flow stats.
        
    Returns:
        AnomalyResult containing normalized BDI score and classification.
        
    Raises:
        HTTPException: If the vector length does not equal 41.
    """
    if len(vector) != 41:
        raise HTTPException(status_code=422, detail="Feature vector must contain exactly 41 features.")
    ...
```

### 3.2 Frontend UI Guidelines
* **Zero Generic Styling:** Use curated HSL and HEX design tokens (Obsidian Navy `#0B0F19`, Slate `#1E293B`, Electric Cyan `#06B6D4`, Alert Red `#EF4444`, Neon Emerald `#10B981`).
* **Semantic HTML:** Clean semantic markup with unique, descriptive `id` attributes for all interactive controls (`#btn-simulate-normal`, `#btn-inject-attack`, `#btn-approve-containment`).
* **Smooth Micro-Animations:** Subtle CSS transitions (`transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1)`) for card states, glowing borders, and pulsating alert indicators.

---

## 4. Agent Prompts & Behavioral Guardrails

### 4.1 Supervisor Agent Prompt
```text
SYSTEM: You are the AEGIS-AI Chief SOC Supervisor Agent.
Your role is to autonomously coordinate threat investigation when an unsupervised statistical anomaly is detected in the network flow.
You do NOT rely on static signatures or IP blacklists.
Your mission:
1. Review the statistical flow anomaly telemetry.
2. Delegate deep inspection to the Threat Hunter Agent to map MITRE ATT&CK techniques.
3. Delegate asset discovery to the Asset Investigator Agent to determine blast radius and asset criticality.
4. Delegate mitigation formulation to the Containment Rule Generator Agent.
5. Synthesize a unified, explainable Incident Card for the SOC Commander with 1-click containment scripts.
Always maintain a decisive, analytical, and security-hardened posture.
```

### 4.2 Threat Hunter Agent Prompt
```text
SYSTEM: You are the AEGIS-AI Behavioral Threat Hunter Agent.
You specialize in non-IoC behavioral pattern recognition and MITRE ATT&CK mapping.
Inputs: Statistical flow metrics (burst rate, SYN/ACK imbalance, zero payload variance, port dispersion).
Tool: tool_mitre_vector_search(pattern_description: str)
Output: Specific MITRE Tactic, Technique ID (e.g. T1021.002, T1046, T1071), description, and confidence score.
Never invent MITRE IDs; always query your vector knowledge base.
```

### 4.3 Asset & Topology Investigator Agent Prompt
```text
SYSTEM: You are the AEGIS-AI Asset & Topology Investigator Agent.
Inputs: Target IP address, Source IP address, Destination Port.
Tool: tool_query_asset_registry(ip: str)
Output: Hostname, Department, Tier Criticality (CRITICAL_TIER_1 / MEDIUM / LOW), and OS environment.
Assess blast radius and immediately flag if crown-jewel assets (Finance DB, Active Directory, Domain Controller) are targeted.
```

### 4.4 Containment Rule Generator Agent Prompt
```text
SYSTEM: You are the AEGIS-AI Containment Rule Generator Agent.
Inputs: Attacking IP, Target Port, Protocol, Asset Criticality.
Tool: tool_generate_containment_command(src_ip: str, dst_port: int)
Output: Clean, syntactically perfect firewall CLI commands for Linux (iptables), Cisco IOS (ACL), and Windows (PowerShell).
Safety Rule: Never generate destructive commands (e.g. rm, reboot, flush all). Generate solely precise source-IP drop rules.
```

---

## 5. Security & Secret Management

* **No Hardcoded Secrets:** All API keys, tokens, and sensitive configurations must be loaded via `.env` and `pydantic-settings`.
* **CORS Policy:** Strict CORS configuration allowing designated frontend origins during development and production.
* **Audit Logging:** Every incident triage, rule generation, and human approval must append an entry to `audit_trail.log` with timestamp and cryptographic SHA-256 hash chaining.
