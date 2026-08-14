"""
Threat Hunter Agent for Project AEGIS-AI.
Specializes in non-IoC behavioral pattern recognition and MITRE ATT&CK mapping.
Rule 1: Zero IoC Dependency - Analyzes purely statistical flow metrics and TTPs.
Rule 4: Deterministic Pydantic Tool Schemas.
Rule 5: Sub-Second Streaming Transparency (AgentThoughtEvent streaming).
"""

import inspect
from typing import Dict, Any, Optional, Callable, Tuple
from backend.app.models.incident import MitreMapping, AgentThoughtEvent
from backend.app.services.cyber_tools import CyberTools


class ThreatHunterAgent:
    """Autonomous Behavioral Threat Hunter Agent.

    Inspects statistical flow metrics (burst rates, byte asymmetry, SYN errors,
    cross-subnet traversal, port dispersion) and queries the local MITRE ATT&CK
    knowledge base to map adversary tactics and techniques with confidence scoring.
    """

    AGENT_NAME = "ThreatHunter"

    def __init__(self, tools: Optional[CyberTools] = None):
        """Initializes the Threat Hunter Agent with security tool interfaces.

        Args:
            tools: Instance or class reference of CyberTools (defaults to CyberTools).
        """
        self.tools = tools or CyberTools()

    async def _emit(
        self,
        step_type: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> AgentThoughtEvent:
        """Helper to create and dispatch an AgentThoughtEvent.

        Args:
            step_type: Event category (THOUGHT | TOOL_CALL | TOOL_OUTPUT | SYNTHESIS).
            message: Human-readable narrative description.
            metadata: Structured contextual dictionary.
            callback: Optional sync or async callback function.

        Returns:
            The created AgentThoughtEvent.
        """
        event = AgentThoughtEvent(
            agent_name=self.AGENT_NAME,
            step_type=step_type,
            message=message,
            metadata=metadata or {},
        )
        if callback is not None:
            if inspect.iscoroutinefunction(callback):
                await callback(event)
            else:
                callback(event)
        return event

    async def investigate(
        self,
        flow_data: Dict[str, Any],
        bdi_score: float,
        on_thought: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> Tuple[MitreMapping, str]:
        """Performs autonomous threat hunting on anomalous network flow telemetry.

        Args:
            flow_data: Statistical flow feature dictionary.
            bdi_score: Behavioral Deviation Index score in [0.0, 1.0].
            on_thought: Optional callback for streaming real-time thought events.

        Returns:
            Tuple of (MitreMapping result, flow analysis summary narrative).
        """
        # Step 1: Initial behavioral thought
        await self._emit(
            step_type="THOUGHT",
            message=(
                f"Analyzing non-payload statistical flow metrics for behavioral anomaly patterns "
                f"(BDI Score: {bdi_score:.4f} CRITICAL). Examining burst volume, flag states, and byte symmetry..."
            ),
            metadata={"bdi_score": bdi_score},
            callback=on_thought,
        )

        # Step 2: Invoke Flow Metrics Deep Inspection Tool
        await self._emit(
            step_type="TOOL_CALL",
            message="Invoking tool_inspect_flow_metrics to parse statistical flow profile...",
            metadata={"tool": "tool_inspect_flow_metrics"},
            callback=on_thought,
        )

        flow_analysis = self.tools.tool_inspect_flow_metrics(flow_data, bdi_score)

        await self._emit(
            step_type="TOOL_OUTPUT",
            message=f"Flow Analysis Result: {flow_analysis}",
            metadata={"flow_analysis": flow_analysis},
            callback=on_thought,
        )

        # Step 3: Invoke MITRE ATT&CK Behavioral Mapping Tool
        await self._emit(
            step_type="TOOL_CALL",
            message="Querying MITRE ATT&CK Knowledge Base for behavioral TTP mapping based on statistical signals...",
            metadata={"tool": "tool_mitre_vector_search"},
            callback=on_thought,
        )

        mitre_mapping = self.tools.tool_mitre_vector_search(flow_data)

        matched_str = ", ".join(mitre_mapping.indicators_matched) if mitre_mapping.indicators_matched else "statistical deviation"
        await self._emit(
            step_type="TOOL_OUTPUT",
            message=(
                f"Matched MITRE technique {mitre_mapping.technique_id} ({mitre_mapping.technique_name}) "
                f"under tactic '{mitre_mapping.tactic}' with {mitre_mapping.confidence:.1f}% confidence. "
                f"Behavioral indicators matched: [{matched_str}]."
            ),
            metadata={
                "technique_id": mitre_mapping.technique_id,
                "confidence": mitre_mapping.confidence,
                "tactic": mitre_mapping.tactic,
            },
            callback=on_thought,
        )

        # Step 4: Final synthesis thought
        await self._emit(
            step_type="SYNTHESIS",
            message=(
                f"Threat Hunter Assessment: High-confidence correlation with MITRE {mitre_mapping.technique_id} "
                f"({mitre_mapping.technique_name}). Recommended mitigation: {mitre_mapping.mitigation}"
            ),
            metadata={"mitre_mapping": mitre_mapping.model_dump()},
            callback=on_thought,
        )

        return mitre_mapping, flow_analysis
