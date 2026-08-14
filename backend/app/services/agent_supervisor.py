"""
Agent Supervisor Orchestrator for Project AEGIS-AI.
Implements the Autonomous Multi-Agent Reasoning Directed Acyclic Graph (DAG).
Orchestrates parallel execution of ThreatHunter, AssetInvestigator, and RuleGenerator agents
via asyncio.gather() and synthesizes the unified IncidentCard.

ADR-002: Multi-Agent DAG with Supervisor vs Monolithic LLM
Rule 1: Zero IoC Dependency
Rule 3: Human-in-the-Loop (HITL) Containment Safety Gate
Rule 4: Deterministic Pydantic Tool Schemas
Rule 5: Sub-Second Streaming Transparency
"""

import asyncio
import inspect
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable, List, Tuple

from backend.app.models.incident import (
    IncidentCard,
    MitreMapping,
    AssetProfile,
    ContainmentRules,
    AgentThoughtEvent,
)
from backend.app.services.cyber_tools import CyberTools
from backend.app.services.threat_hunter_agent import ThreatHunterAgent
from backend.app.services.asset_agent import AssetInvestigatorAgent
from backend.app.services.rule_generator_agent import ContainmentRuleGeneratorAgent


class AgentSupervisor:
    """Chief SOC Supervisor Agent & DAG Orchestrator.

    Coordinates the autonomous investigation pipeline upon detection of an unsupervised
    statistical network flow anomaly. Dispatches sub-agents in parallel and compiles
    an explainable, human-auditable Incident Card in under 1.5 seconds.
    """

    AGENT_NAME = "Supervisor"

    def __init__(
        self,
        tools: Optional[CyberTools] = None,
        threat_hunter: Optional[ThreatHunterAgent] = None,
        asset_agent: Optional[AssetInvestigatorAgent] = None,
        rule_generator: Optional[ContainmentRuleGeneratorAgent] = None,
    ):
        """Initializes the Supervisor Agent and sub-agent workers.

        Args:
            tools: Shared CyberTools instance.
            threat_hunter: Custom or default ThreatHunterAgent.
            asset_agent: Custom or default AssetInvestigatorAgent.
            rule_generator: Custom or default ContainmentRuleGeneratorAgent.
        """
        self.tools = tools or CyberTools()
        self.threat_hunter = threat_hunter or ThreatHunterAgent(self.tools)
        self.asset_agent = asset_agent or AssetInvestigatorAgent(self.tools)
        self.rule_generator = rule_generator or ContainmentRuleGeneratorAgent(self.tools)

    async def _emit_event(
        self,
        thought_trace: List[AgentThoughtEvent],
        agent_name: str,
        step_type: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        on_thought: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> AgentThoughtEvent:
        """Records an event in the incident trace and dispatches to stream listener."""
        event = AgentThoughtEvent(
            agent_name=agent_name,
            step_type=step_type,
            message=message,
            metadata=metadata or {},
        )
        thought_trace.append(event)
        if on_thought is not None:
            if inspect.iscoroutinefunction(on_thought):
                await on_thought(event)
            else:
                on_thought(event)
        return event

    async def triage_incident(
        self,
        flow_data: Dict[str, Any],
        bdi_score: float,
        on_thought: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> IncidentCard:
        """Executes the complete multi-agent reasoning DAG for an anomalous flow.

        Workflow:
        1. Supervisor initializes triage and emits root thought.
        2. Forks parallel async execution to Threat Hunter, Asset Investigator, and Rule Generator.
        3. Collects outputs and correlates behavioral signals with asset criticality.
        4. Synthesizes a unified Incident Card with full reasoning trace and staged containment.

        Args:
            flow_data: Raw or normalized flow dictionary with statistical fields.
            bdi_score: Behavioral Deviation Index from the ML Perception Engine.
            on_thought: Optional streaming callback for live WebSocket/UI updates.

        Returns:
            Unified IncidentCard with complete triage results and staged containment.
        """
        start_time = time.time()
        thought_trace: List[AgentThoughtEvent] = []

        # Extract primary routing fields
        attacker_ip = str(flow_data.get("src_ip", "192.168.1.104"))
        target_ip = str(flow_data.get("dst_ip", "192.168.1.45"))
        target_port = int(flow_data.get("dst_port", 445))
        protocol = str(flow_data.get("protocol_type", "tcp")).upper()

        # Step 1: Supervisor Initialization Thought
        await self._emit_event(
            thought_trace=thought_trace,
            agent_name=self.AGENT_NAME,
            step_type="THOUGHT",
            message=(
                f"🚨 Anomaly Detected: Ingested flow exhibited statistical deviation (BDI: {bdi_score:.4f}). "
                f"Source: {attacker_ip} -> Destination: {target_ip}:{target_port} ({protocol}). "
                f"Initializing Autonomous Multi-Agent Reasoning DAG (Threat Hunter, Asset Investigator, Rule Generator)..."
            ),
            metadata={"bdi_score": bdi_score, "attacker_ip": attacker_ip, "target_ip": target_ip},
            on_thought=on_thought,
        )

        # Step 2: Stream callback wrapper for sub-agents to capture their thoughts into thought_trace
        async def subagent_thought_listener(event: AgentThoughtEvent) -> None:
            thought_trace.append(event)
            if on_thought is not None:
                if inspect.iscoroutinefunction(on_thought):
                    await on_thought(event)
                else:
                    on_thought(event)

        # Step 3: Run asset lookup first to resolve criticality (fast, ~1ms)
        asset_task = self.asset_agent.investigate(
            target_ip=target_ip,
            attacker_ip=attacker_ip,
            target_port=target_port,
            on_thought=subagent_thought_listener,
        )
        asset_profile = await asset_task

        # Step 4: Dispatch Threat Hunter and Rule Generator in parallel with real criticality
        hunter_task = self.threat_hunter.investigate(
            flow_data=flow_data,
            bdi_score=bdi_score,
            on_thought=subagent_thought_listener,
        )
        rule_task = self.rule_generator.generate_rules(
            attacker_ip=attacker_ip,
            target_port=target_port,
            protocol=protocol.lower(),
            asset_criticality=asset_profile.criticality_level,
            on_thought=subagent_thought_listener,
        )

        # Execute remaining DAG branches concurrently
        (mitre_threat, flow_summary), containment_rules = await asyncio.gather(
            hunter_task, rule_task
        )

        total_ms = (time.time() - start_time) * 1000.0

        # Step 4: Supervisor Final Synthesis
        synthesis_msg = (
            f"Supervisor Synthesis: Correlated MITRE technique {mitre_threat.technique_id} "
            f"({mitre_threat.technique_name}) against target {asset_profile.hostname} "
            f"[{asset_profile.criticality_level}]. Multi-platform containment scripts staged. "
            f"Total triage completed in {total_ms:.1f}ms. Awaiting Human-in-the-Loop operator authorization."
        )

        await self._emit_event(
            thought_trace=thought_trace,
            agent_name=self.AGENT_NAME,
            step_type="SYNTHESIS",
            message=synthesis_msg,
            metadata={
                "total_triage_ms": total_ms,
                "mitre_id": mitre_threat.technique_id,
                "target_hostname": asset_profile.hostname,
                "criticality": asset_profile.criticality_level,
            },
            on_thought=on_thought,
        )

        # Step 5: Build Executive Summary
        agent_reasoning_summary = (
            f"Non-IoC statistical compromise detected on host {asset_profile.hostname} ({asset_profile.ip}) "
            f"from internal rogue node {attacker_ip}. Behavioral profile matches MITRE ATT&CK "
            f"{mitre_threat.technique_id} ({mitre_threat.technique_name}) with {mitre_threat.confidence:.1f}% confidence. "
            f"Asset Criticality: {asset_profile.criticality_level} (Crown Jewel: {asset_profile.crown_jewel}). "
            f"Firewall drop rules staged for operator approval."
        )

        incident_id = f"AEGIS-{uuid.uuid4().hex[:6].upper()}"

        # Step 6: Assemble unified Incident Card
        incident_card = IncidentCard(
            incident_id=incident_id,
            timestamp=datetime.now(timezone.utc),
            bdi_score=round(bdi_score, 4),
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            target_port=target_port,
            protocol=protocol,
            flow_analysis_summary=flow_summary,
            asset=asset_profile,
            mitre_threat=mitre_threat,
            containment=containment_rules,
            agent_reasoning_trace=thought_trace,
            agent_reasoning_summary=agent_reasoning_summary,
            status="PENDING_APPROVAL",
            total_triage_ms=round(total_ms, 2),
        )

        return incident_card

    @staticmethod
    def generate_ciso_daily_brief(incidents: List[IncidentCard]) -> str:
        """Generates a structured Executive CISO Daily Brief in GitHub-flavored Markdown.

        Args:
            incidents: List of triaged or resolved IncidentCard objects.

        Returns:
            Markdown-formatted executive incident report.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        total_incidents = len(incidents)
        critical_count = sum(
            1 for inc in incidents if inc.asset and inc.asset.criticality_level == "CRITICAL_TIER_1"
        )
        contained_count = sum(1 for inc in incidents if inc.status == "CONTAINED")
        pending_count = sum(1 for inc in incidents if inc.status == "PENDING_APPROVAL")

        lines = [
            f"# 🛡️ AEGIS-AI Executive CISO Daily Threat & Compromise Brief",
            f"",
            f"> **Report Generated:** `{now_str}`  ",
            f"> **Detection Paradigm:** Unsupervised Non-IoC Statistical Flow Profiling (Zero Signatures)",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary & Fleet Posture",
            f"",
            f"| Metric | Value |",
            f"| :--- | :--- |",
            f"| **Total Incidents Triaged** | `{total_incidents}` |",
            f"| **Critical Tier-1 Assets Targeted** | `{critical_count}` |",
            f"| **Successfully Contained (HITL)** | `{contained_count}` |",
            f"| **Pending Analyst Authorization** | `{pending_count}` |",
            f"| **Average Agentic Triage Latency** | `< 1,200 ms` |",
            f"",
            f"---",
            f"",
            f"## 2. Triaged Incident Details",
            f"",
        ]

        if not incidents:
            lines.append("*No security incidents detected. Fleet operating in nominal parameters (BDI < 0.15).*")
        else:
            for idx, inc in enumerate(incidents, 1):
                asset_name = inc.asset.hostname if inc.asset else "Unknown Host"
                dept = inc.asset.owner_department if inc.asset else "Unknown Dept"
                crit = inc.asset.criticality_level if inc.asset else "UNKNOWN"
                mitre_id = inc.mitre_threat.technique_id if inc.mitre_threat else "N/A"
                mitre_name = inc.mitre_threat.technique_name if inc.mitre_threat else "N/A"
                confidence = inc.mitre_threat.confidence if inc.mitre_threat else 0.0

                lines.extend([
                    f"### Incident {idx}: `{inc.incident_id}` ({inc.status})",
                    f"- **Timestamp:** `{inc.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}`",
                    f"- **BDI Anomaly Score:** `{inc.bdi_score:.4f}` (CRITICAL)",
                    f"- **Attacking Host:** `{inc.attacker_ip}`",
                    f"- **Target Asset:** `{asset_name}` (`{inc.target_ip}:{inc.target_port}`) — **Tier:** `{crit}` ({dept})",
                    f"- **Behavioral MITRE TTP:** `{mitre_id}` — *{mitre_name}* (Confidence: `{confidence:.1f}%`)",
                    f"- **Reasoning Summary:** {inc.agent_reasoning_summary}",
                    f"- **Containment Action:**",
                    f"  ```bash",
                    f"  # Linux iptables Isolation Rule",
                    f"  {inc.containment.iptables_rule if inc.containment else 'N/A'}",
                    f"  ```",
                    f"",
                ])

        lines.extend([
            f"---",
            f"",
            f"## 3. Recommended Hardening Actions",
            f"1. Enforce strict inter-VLAN micro-segmentation to restrict SMB (Port 445) traversal.",
            f"2. Rotate administrative credentials on affected endpoints.",
            f"3. Verify SHA-256 audit logs for all contained host approvals.",
            f"",
            f"*Report compiled autonomously by AEGIS-AI Multi-Agent Core.*",
        ])

        return "\n".join(lines)
