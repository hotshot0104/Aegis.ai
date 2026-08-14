"""
Asset & Topology Investigator Agent for Project AEGIS-AI.
Queries internal subnet registries to resolve asset identities, departmental ownership,
and criticality tiers to establish the blast radius of anomalous activity.
Rule 4: Deterministic Pydantic Tool Schemas.
Rule 5: Sub-Second Streaming Transparency.
"""

import inspect
from typing import Dict, Any, Optional, Callable
from backend.app.models.incident import AssetProfile, AgentThoughtEvent
from backend.app.services.cyber_tools import CyberTools


class AssetInvestigatorAgent:
    """Autonomous Asset & Topology Investigator Agent.

    Resolves target and source asset identities from the enterprise asset inventory,
    determines crown-jewel status, assesses subnet exposure, and computes blast radius.
    """

    AGENT_NAME = "AssetInvestigator"

    def __init__(self, tools: Optional[CyberTools] = None):
        """Initializes the Asset Investigator Agent.

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
        target_ip: str,
        attacker_ip: str,
        target_port: int,
        on_thought: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> AssetProfile:
        """Performs autonomous asset inventory query and blast radius assessment.

        Args:
            target_ip: Destination IP address under investigation.
            attacker_ip: Source IP address initiating the anomalous flow.
            target_port: Destination port being accessed.
            on_thought: Optional callback for streaming real-time thought events.

        Returns:
            AssetProfile model populated with host identity and criticality metadata.
        """
        # Step 1: Initial thought
        await self._emit(
            step_type="THOUGHT",
            message=(
                f"Querying internal enterprise subnet registry for asset profile on target IP {target_ip} "
                f"(targeted on port {target_port} by rogue source {attacker_ip})..."
            ),
            metadata={"target_ip": target_ip, "attacker_ip": attacker_ip, "target_port": target_port},
            callback=on_thought,
        )

        # Step 2: Invoke Asset Query Tool
        await self._emit(
            step_type="TOOL_CALL",
            message=f"Invoking tool_query_asset_registry(ip='{target_ip}')...",
            metadata={"tool": "tool_query_asset_registry", "ip": target_ip},
            callback=on_thought,
        )

        asset = self.tools.tool_query_asset_registry(target_ip)

        await self._emit(
            step_type="TOOL_OUTPUT",
            message=(
                f"Target node resolved: {asset.hostname} [{asset.ip}] | Dept: {asset.owner_department} | "
                f"Criticality: {asset.criticality_level} | Crown Jewel: {'YES 👑' if asset.crown_jewel else 'NO'} | "
                f"OS: {asset.os_type} | Subnet: {asset.subnet}"
            ),
            metadata={"asset": asset.model_dump()},
            callback=on_thought,
        )

        # Step 3: Synthesis & Blast Radius Assessment
        if asset.crown_jewel or asset.criticality_level == "CRITICAL_TIER_1":
            synthesis_msg = (
                f"🚨 CRITICAL ASSET ALERT: Target host '{asset.hostname}' ({asset.ip}) is a designated "
                f"Crown Jewel enterprise asset ({asset.owner_department}). Blast radius risk is SEVERE. "
                f"Immediate high-priority network containment is required to prevent data breach."
            )
        else:
            synthesis_msg = (
                f"Asset Assessment: Target host '{asset.hostname}' ({asset.ip}) is classified as "
                f"{asset.criticality_level} in {asset.owner_department}. Lateral spread risk contained to {asset.subnet}."
            )

        await self._emit(
            step_type="SYNTHESIS",
            message=synthesis_msg,
            metadata={"crown_jewel": asset.crown_jewel, "criticality_level": asset.criticality_level},
            callback=on_thought,
        )

        return asset
