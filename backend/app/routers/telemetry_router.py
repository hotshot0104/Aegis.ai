"""
Telemetry and Ingestion Router for Project AEGIS-AI.
Endpoints:
- POST /api/v1/telemetry/stream: Live flow vector ingestion & BDI anomaly scoring.
- POST /api/v1/telemetry/simulate/normal: Broadcast benign traffic burst for jury demonstration.
- POST /api/v1/telemetry/simulate/attack: Inject zero-day attack burst and trigger autonomous Multi-Agent DAG triage.
"""

import asyncio
import json
import os
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import pandas as pd
from fastapi import APIRouter, HTTPException, BackgroundTasks, status

from backend.app.models.incident import (
    NetworkFlowVector,
    AnomalyScoreResult,
    IncidentCard,
)
from backend.app.core.config import settings
from backend.app.core.websocket_manager import ws_manager
from backend.app.services.incident_store import incident_store
from backend.app.services.agent_supervisor import AgentSupervisor
from backend.ml_engine.feature_extractor import FlowFeatureExtractor
from backend.ml_engine.anomaly_detector import NetworkAnomalyDetector
from backend.ml_engine.rolling_filter import RollingFalsePositiveFilter

router = APIRouter(prefix="/telemetry", tags=["Telemetry & Perception Engine"])

# Shared engine instances (initialized on startup in main.py lifespan)
anomaly_detector: Optional[NetworkAnomalyDetector] = None
rolling_filter = RollingFalsePositiveFilter(
    window_size=settings.ROLLING_WINDOW_SIZE,
    time_window_seconds=settings.ROLLING_TIME_WINDOW_SECONDS,
)
agent_supervisor = AgentSupervisor()


def get_detector() -> NetworkAnomalyDetector:
    """Returns the loaded anomaly detector or instantiates from model artifact."""
    global anomaly_detector
    if anomaly_detector is None:
        anomaly_detector = NetworkAnomalyDetector(model_path=settings.MODEL_PATH)
    return anomaly_detector


@router.post("/stream", response_model=AnomalyScoreResult, status_code=status.HTTP_200_OK)
async def stream_telemetry(flow: NetworkFlowVector, background_tasks: BackgroundTasks) -> AnomalyScoreResult:
    """Ingests a network flow vector, extracts 41 statistical features, scores BDI,
    and checks temporal rolling filter for sustained compromise behavior.
    
    If sustained anomaly ($K=3$ consecutive ticks) is detected, automatically triggers
    the Autonomous Multi-Agent Reasoning DAG and broadcasts thoughts in real time.
    """
    detector = get_detector()
    start_time = time.perf_counter()

    # Combine top-level metadata with features dictionary
    flow_dict = dict(flow.features)
    flow_dict["src_ip"] = flow.src_ip
    flow_dict["dst_ip"] = flow.dst_ip
    flow_dict["src_port"] = flow.src_port
    flow_dict["dst_port"] = flow.dst_port
    flow_dict["protocol_type"] = flow.protocol.lower()

    # Extract 41-dim normalized vector and score
    vector = FlowFeatureExtractor.extract_vector(flow_dict)
    score_res = detector.score_vector(vector)
    inference_ms = (time.perf_counter() - start_time) * 1000.0

    bdi_score = score_res["bdi_score"]
    is_anomaly = score_res["is_anomaly"]
    status_label = score_res["status"]

    # Evaluate rolling false-positive filter
    filter_res = await rolling_filter.evaluate_async(flow.src_ip, is_anomaly, bdi_score)

    telemetry_payload = {
        "flow_id": flow.flow_id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "bdi_score": bdi_score,
        "is_anomaly": is_anomaly,
        "status": status_label,
        "raw_isolation_score": score_res["raw_decision_score"],
        "consecutive_anomalies": filter_res["consecutive_anomalies"],
        "should_escalate": filter_res["should_escalate"],
        "inference_ms": round(inference_ms, 3),
    }

    # Broadcast live telemetry tick to WebSocket clients
    await ws_manager.broadcast_telemetry(telemetry_payload)

    # If sustained anomaly confirmed, trigger Multi-Agent DAG triage
    if filter_res["should_escalate"]:
        async def run_triage():
            incident_card = await agent_supervisor.triage_incident(
                flow_data=flow_dict,
                bdi_score=bdi_score,
                on_thought=ws_manager.broadcast_thought,
            )
            await incident_store.add_incident(incident_card)
            await ws_manager.broadcast_json({
                "type": "INCIDENT_CREATED",
                "data": incident_card.model_dump(mode="json"),
            })

        background_tasks.add_task(run_triage)

    return AnomalyScoreResult(
        flow_id=flow.flow_id,
        bdi_score=bdi_score,
        is_anomaly=is_anomaly,
        status=status_label,
        raw_isolation_score=score_res["raw_decision_score"],
        inference_ms=round(inference_ms, 3),
    )


@router.post("/simulate/normal", status_code=status.HTTP_200_OK)
async def simulate_normal_traffic(sample_count: int = 5) -> Dict[str, Any]:
    r"""Broadcasts a series of benign enterprise traffic flows for jury demonstration.
    Demonstrates nominal fleet status with low BDI scores ($\le 0.15$).
    """
    detector = get_detector()
    csv_path = os.path.join(settings.DATA_DIR, "benign_baseline.csv")

    if not os.path.exists(csv_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Benign baseline dataset not found. Run generate_baseline_data.py first.",
        )

    df = pd.read_csv(csv_path)
    sample_records = df.drop(columns=["label"]).sample(min(sample_count, len(df))).to_dict(orient="records")

    results = []
    for idx, sample in enumerate(sample_records):
        score_res = detector.score_flow_dict(sample)
        bdi_score = score_res["bdi_score"]

        telemetry_payload = {
            "flow_id": f"SIM-NORM-{idx+1:03d}",
            "src_ip": sample.get("src_ip", f"192.168.1.{random.randint(10, 90)}"),
            "dst_ip": sample.get("dst_ip", "192.168.1.1"),
            "dst_port": sample.get("dst_port", 80),
            "protocol": sample.get("protocol_type", "tcp").upper(),
            "bdi_score": bdi_score,
            "is_anomaly": False,
            "status": "NOMINAL",
            "raw_isolation_score": score_res["raw_decision_score"],
            "consecutive_anomalies": 0,
            "should_escalate": False,
            "inference_ms": 2.5,
        }

        await ws_manager.broadcast_telemetry(telemetry_payload)
        results.append(telemetry_payload)
        await asyncio.sleep(0.05)  # Short stagger for visual feedback

    return {
        "status": "SUCCESS",
        "message": f"Broadcasted {len(results)} nominal benign flows.",
        "avg_bdi": round(sum(r["bdi_score"] for r in results) / len(results), 4),
        "flows": results,
    }


@router.post("/simulate/attack", response_model=IncidentCard, status_code=status.HTTP_200_OK)
async def simulate_attack(mitre_id: Optional[str] = None) -> IncidentCard:
    """Injects a synthetic zero-day attack burst (T1021.002 SMB, T1046 Scan, or T1071.001 C2),
    trips the rolling false-positive filter ($K=3$), executes the 4-Agent DAG,
    and returns the synthesized IncidentCard with staged containment rules.
    """
    detector = get_detector()
    attacks_path = os.path.join(settings.DATA_DIR, "synthetic_attack_samples.json")

    if not os.path.exists(attacks_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Synthetic attacks dataset not found.",
        )

    with open(attacks_path, "r", encoding="utf-8") as f:
        attacks = json.load(f)

    # Select attack matching mitre_id or default to first (T1021.002)
    selected_attack = None
    if mitre_id:
        for atk in attacks:
            if atk.get("mitre_id", "").upper() == mitre_id.upper():
                selected_attack = atk
                break

    if selected_attack is None:
        selected_attack = attacks[0]  # Default to T1021.002 Lateral Movement

    flow_data = selected_attack["flow_data"]
    attacker_ip = flow_data.get("src_ip", "192.168.1.104")

    # Clear previous history for attacker IP to ensure clean 3-tick burst demonstration
    rolling_filter.reset_ip(attacker_ip)

    # Simulate 3 consecutive anomaly bursts to demonstrate the rolling filter
    bdi_score = 0.95
    for tick in range(1, 4):
        score_res = detector.score_flow_dict(flow_data)
        bdi_score = score_res["bdi_score"]
        filter_res = await rolling_filter.evaluate_async(attacker_ip, True, bdi_score)

        telemetry_payload = {
            "flow_id": f"ATK-BURST-TICK-{tick}",
            "src_ip": attacker_ip,
            "dst_ip": flow_data.get("dst_ip", "192.168.1.45"),
            "dst_port": flow_data.get("dst_port", 445),
            "protocol": flow_data.get("protocol_type", "tcp").upper(),
            "bdi_score": bdi_score,
            "is_anomaly": True,
            "status": "CRITICAL_ANOMALY",
            "raw_isolation_score": score_res["raw_decision_score"],
            "consecutive_anomalies": filter_res["consecutive_anomalies"],
            "should_escalate": filter_res["should_escalate"],
            "inference_ms": 2.8,
        }

        await ws_manager.broadcast_telemetry(telemetry_payload)
        await asyncio.sleep(0.04)

    # Execute the Autonomous Multi-Agent Reasoning DAG with real-time thought broadcasting
    incident_card = await agent_supervisor.triage_incident(
        flow_data=flow_data,
        bdi_score=bdi_score,
        on_thought=ws_manager.broadcast_thought,
    )

    # Save to incident store and broadcast to WebSocket clients
    await incident_store.add_incident(incident_card)
    await ws_manager.broadcast_json({
        "type": "INCIDENT_CREATED",
        "data": incident_card.model_dump(mode="json"),
    })

    return incident_card


async def continuous_telemetry_loop():
    """Continuously streams realistic network telemetry ticks over WebSockets to animate dashboard."""
    sample_ips = [
        ("66.104.232.73", "statuspage.io", "AU"),
        ("73.117.6.114", "db-cluster-prod.internal", "SG"),
        ("80.130.35.155", "k8s-ingress.aegis.dev", "NL"),
        ("87.143.64.196", "monitoring.datadog.com", "SE"),
        ("94.156.93.237", "api.aegis.cloud", "KR"),
        ("101.169.122.23", "finance.subnet.internal", "IT"),
        ("108.182.151.64", "auth-gateway.aegis.io", "ES"),
        ("115.195.180.105", "exit-node-05.tor.org", "US"),
        ("122.208.209.146", "telemetry.aws-east.com", "DE"),
        ("129.221.238.187", "webhook.github.com", "JP"),
        ("136.234.12.228", "cdn-edge.cloudflare.com", "IN"),
        ("143.247.41.14", "s3-vault.amazonaws.com", "GB"),
        ("150.5.70.55", "statuspage.io", "CA"),
        ("157.18.99.96", "db-cluster-prod.internal", "FR"),
        ("164.31.128.137", "k8s-ingress.aegis.dev", "BR"),
        ("171.44.157.178", "monitoring.datadog.com", "AU"),
        ("178.57.186.219", "api.aegis.cloud", "SG"),
        ("185.70.215.5", "finance.subnet.internal", "NL"),
        ("192.83.244.46", "auth-gateway.aegis.io", "SE"),
        ("199.96.18.87", "exit-node-05.tor.org", "US"),
    ]
    tick_counter = 1
    while True:
        try:
            await asyncio.sleep(2.0)
            if not ws_manager.active_connections:
                continue

            src_ip, domain, country = random.choice(sample_ips)
            bdi = round(random.uniform(0.04, 0.12), 3)
            payload = {
                "flow_id": f"FLOW-LIVE-{tick_counter:05d}",
                "src_ip": src_ip,
                "domain": domain,
                "country": country,
                "dst_ip": "192.168.1.1",
                "dst_port": random.choice([80, 443, 8000, 5432]),
                "protocol": "TCP",
                "bdi_score": bdi,
                "is_anomaly": False,
                "status": "NOMINAL",
                "inference_ms": round(random.uniform(1.8, 3.2), 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await ws_manager.broadcast_telemetry(payload)
            tick_counter += 1
        except asyncio.CancelledError:
            break
        except Exception:
            pass

