"""
Integration and Unit Tests for Multi-Agent Reasoning DAG (Phase 2).
Tests:
1. CyberTools deterministic behavior and schema validity (Rule 4).
2. Individual sub-agents (ThreatHunter, AssetInvestigator, RuleGenerator).
3. Chief SOC Supervisor Agent DAG execution and asyncio.gather() parallelization.
4. Real-time AgentThoughtEvent streaming callback propagation (Rule 5).
5. Triage latency benchmark (< 1500 ms target).
6. CISO Executive Daily Brief Markdown generation (FR-07).
"""

import time
import pytest
import asyncio
from typing import List

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
from backend.app.services.agent_supervisor import AgentSupervisor


@pytest.fixture
def smb_attack_flow():
    """Returns sample SMB lateral movement attack flow."""
    return {
        "src_ip": "192.168.1.104",
        "dst_ip": "192.168.1.45",
        "dst_port": 445,
        "protocol_type": "tcp",
        "service": "smb",
        "flag": "SF",
        "duration": 0.05,
        "src_bytes": 1450,
        "dst_bytes": 890,
        "count": 180,
        "srv_count": 175,
        "same_srv_rate": 0.98,
        "diff_srv_rate": 0.02,
        "serror_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 250,
        "dst_host_same_srv_rate": 0.98,
        "dst_host_diff_srv_rate": 0.02,
        "dst_host_srv_diff_host_rate": 0.85,
    }


def test_cyber_tools_flow_inspection(smb_attack_flow):
    """Verify tool_inspect_flow_metrics produces structured narrative."""
    narrative = CyberTools.tool_inspect_flow_metrics(smb_attack_flow, bdi_score=0.94)
    assert isinstance(narrative, str)
    assert "192.168.1.104" in narrative
    assert "192.168.1.45:445" in narrative
    assert "BDI Score: 0.9400" in narrative


def test_cyber_tools_asset_registry():
    """Verify tool_query_asset_registry resolves known assets and fallbacks."""
    # Known Crown Jewel
    asset_finance = CyberTools.tool_query_asset_registry("192.168.1.45")
    assert isinstance(asset_finance, AssetProfile)
    assert asset_finance.hostname == "DB-PROD-FINANCE-01"
    assert asset_finance.criticality_level == "CRITICAL_TIER_1"
    assert asset_finance.crown_jewel is True

    # Known Workstation
    asset_workstation = CyberTools.tool_query_asset_registry("192.168.1.104")
    assert asset_workstation.hostname == "ENG-WORKSTATION-88"
    assert asset_workstation.criticality_level == "LOW_TIER_3"

    # Unknown IP fallback
    asset_unknown = CyberTools.tool_query_asset_registry("10.0.0.99")
    assert asset_unknown.hostname == "NODE-10-0-0-99"
    assert asset_unknown.criticality_level == "MEDIUM"


def test_cyber_tools_mitre_mapping(smb_attack_flow):
    """Verify tool_mitre_vector_search matches SMB Lateral Movement (T1021.002)."""
    mitre_res = CyberTools.tool_mitre_vector_search(smb_attack_flow)
    assert isinstance(mitre_res, MitreMapping)
    assert mitre_res.technique_id == "T1021.002"
    assert mitre_res.tactic == "Lateral Movement"
    assert mitre_res.confidence >= 80.0
    assert len(mitre_res.indicators_matched) > 0


def test_cyber_tools_containment_generation():
    """Verify tool_generate_containment_command generates safe firewall commands."""
    rules = CyberTools.tool_generate_containment_command(
        src_ip="192.168.1.104", dst_port=445, protocol="tcp"
    )
    assert isinstance(rules, ContainmentRules)
    assert "iptables -I INPUT 1 -s 192.168.1.104" in rules.iptables_rule
    assert "access-list 101 deny tcp host 192.168.1.104" in rules.cisco_acl
    assert "New-NetFirewallRule" in rules.powershell_command
    assert "192.168.1.104" in rules.powershell_command


@pytest.mark.asyncio
async def test_threat_hunter_agent(smb_attack_flow):
    """Verify ThreatHunterAgent emits streaming thoughts and returns MitreMapping."""
    agent = ThreatHunterAgent()
    streamed_events: List[AgentThoughtEvent] = []

    async def thought_listener(event: AgentThoughtEvent):
        streamed_events.append(event)

    mitre_threat, flow_summary = await agent.investigate(
        flow_data=smb_attack_flow,
        bdi_score=0.94,
        on_thought=thought_listener,
    )

    assert mitre_threat.technique_id == "T1021.002"
    assert len(flow_summary) > 10
    assert len(streamed_events) >= 4  # THOUGHT, TOOL_CALL, TOOL_OUTPUT, SYNTHESIS
    assert any(e.step_type == "TOOL_CALL" for e in streamed_events)
    assert any(e.step_type == "SYNTHESIS" for e in streamed_events)


@pytest.mark.asyncio
async def test_asset_investigator_agent():
    """Verify AssetInvestigatorAgent resolves target metadata and flags crown jewels."""
    agent = AssetInvestigatorAgent()
    streamed_events: List[AgentThoughtEvent] = []

    asset = await agent.investigate(
        target_ip="192.168.1.45",
        attacker_ip="192.168.1.104",
        target_port=445,
        on_thought=lambda e: streamed_events.append(e),
    )

    assert asset.hostname == "DB-PROD-FINANCE-01"
    assert asset.criticality_level == "CRITICAL_TIER_1"
    assert len(streamed_events) >= 3


@pytest.mark.asyncio
async def test_rule_generator_agent():
    """Verify ContainmentRuleGeneratorAgent compiles non-destructive isolation rules."""
    agent = ContainmentRuleGeneratorAgent()
    streamed_events: List[AgentThoughtEvent] = []

    rules = await agent.generate_rules(
        attacker_ip="192.168.1.104",
        target_port=445,
        protocol="tcp",
        asset_criticality="CRITICAL_TIER_1",
        on_thought=lambda e: streamed_events.append(e),
    )

    assert "iptables" in rules.iptables_rule
    assert "access-list 101" in rules.cisco_acl
    assert len(streamed_events) >= 3


@pytest.mark.asyncio
async def test_supervisor_dag_e2e_triage(smb_attack_flow):
    """Verify full Supervisor DAG execution, latency, and IncidentCard schema."""
    supervisor = AgentSupervisor()
    streamed_events: List[AgentThoughtEvent] = []

    async def thought_logger(e: AgentThoughtEvent):
        streamed_events.append(e)

    start = time.perf_counter()
    incident_card = await supervisor.triage_incident(
        flow_data=smb_attack_flow,
        bdi_score=0.945,
        on_thought=thought_logger,
    )
    duration_ms = (time.perf_counter() - start) * 1000.0

    # 1. Performance Target: Under 1500 ms (NFR-01)
    assert duration_ms < 1500.0, f"DAG triage took {duration_ms:.2f} ms (Target < 1500 ms)"

    # 2. Schema Integrity
    assert isinstance(incident_card, IncidentCard)
    assert incident_card.incident_id.startswith("AEGIS-")
    assert incident_card.bdi_score == 0.945
    assert incident_card.attacker_ip == "192.168.1.104"
    assert incident_card.target_ip == "192.168.1.45"
    assert incident_card.status == "PENDING_APPROVAL"

    # 3. Sub-Agent Outputs Correlated
    assert incident_card.asset is not None
    assert incident_card.asset.hostname == "DB-PROD-FINANCE-01"
    assert incident_card.mitre_threat is not None
    assert incident_card.mitre_threat.technique_id == "T1021.002"
    assert incident_card.containment is not None
    assert "192.168.1.104" in incident_card.containment.iptables_rule

    # 4. Streaming Trace Captured
    assert len(incident_card.agent_reasoning_trace) >= 10
    assert len(streamed_events) >= 10
    agents_involved = {e.agent_name for e in incident_card.agent_reasoning_trace}
    assert "Supervisor" in agents_involved
    assert "ThreatHunter" in agents_involved
    assert "AssetInvestigator" in agents_involved
    assert "RuleGenerator" in agents_involved

    # 5. Executive Summary Generated
    assert len(incident_card.agent_reasoning_summary) > 20


def test_ciso_daily_brief_generation(smb_attack_flow):
    """Verify CISO daily brief report markdown formatting."""
    supervisor = AgentSupervisor()
    incident_card = asyncio.run(
        supervisor.triage_incident(smb_attack_flow, bdi_score=0.95)
    )

    report_md = supervisor.generate_ciso_daily_brief([incident_card])
    assert isinstance(report_md, str)
    assert "# 🛡️ AEGIS-AI Executive CISO Daily Threat & Compromise Brief" in report_md
    assert incident_card.incident_id in report_md
    assert "DB-PROD-FINANCE-01" in report_md
    assert "T1021.002" in report_md
    assert "iptables" in report_md
