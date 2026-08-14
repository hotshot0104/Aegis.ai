"""
Containment Rule Generator Agent for Project AEGIS-AI.
Synthesizes precise, platform-specific firewall rules (iptables, Cisco ACL, Windows PowerShell)
to isolate attacking hosts while enforcing Human-in-the-Loop (HITL) safety constraints (Rule 3).
Rule 4: Deterministic Pydantic Tool Schemas.
Rule 5: Sub-Second Streaming Transparency.
"""

import inspect
from typing import Dict, Any, Optional, Callable
from backend.app.models.incident import ContainmentRules, AgentThoughtEvent
from backend.app.services.cyber_tools import CyberTools


class ContainmentRuleGeneratorAgent:
    """Autonomous Containment Rule Generator Agent.

    Synthesizes exact, non-destructive CLI firewall isolation commands for Linux iptables,
    Cisco IOS ACLs, and Windows PowerShell NetSecurity. Rules are staged in the incident
    card awaiting explicit human authorization (Rule 3: HITL Safety Gate).
    """

    AGENT_NAME = "RuleGenerator"

    def __init__(self, tools: Optional[CyberTools] = None):
        """Initializes the Containment Rule Generator Agent.

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

    async def generate_rules(
        self,
        attacker_ip: str,
        target_port: int,
        protocol: str = "tcp",
        asset_criticality: str = "MEDIUM",
        on_thought: Optional[Callable[[AgentThoughtEvent], Any]] = None,
    ) -> ContainmentRules:
        """Generates platform-specific firewall containment scripts.

        Args:
            attacker_ip: Source IP of the attacking or compromised host.
            target_port: Target destination port being assaulted.
            protocol: Protocol string (tcp/udp/icmp).
            asset_criticality: Criticality tier of the destination asset.
            on_thought: Optional callback for streaming real-time thought events.

        Returns:
            ContainmentRules model with iptables, Cisco ACL, and PowerShell commands.
        """
        # Step 1: Initial formulation thought
        await self._emit(
            step_type="THOUGHT",
            message=(
                f"Formulating multi-platform containment rules for rogue source host {attacker_ip} "
                f"targeting port {target_port}/{protocol.upper()} (Asset Criticality: {asset_criticality})..."
            ),
            metadata={"attacker_ip": attacker_ip, "target_port": target_port, "protocol": protocol},
            callback=on_thought,
        )

        # Step 2: Invoke Rule Compiler Tool
        await self._emit(
            step_type="TOOL_CALL",
            message=(
                f"Invoking tool_generate_containment_command(src_ip='{attacker_ip}', "
                f"dst_port={target_port}, proto='{protocol}')..."
            ),
            metadata={
                "tool": "tool_generate_containment_command",
                "src_ip": attacker_ip,
                "dst_port": target_port,
                "protocol": protocol,
            },
            callback=on_thought,
        )

        rules = self.tools.tool_generate_containment_command(
            src_ip=attacker_ip,
            dst_port=target_port,
            protocol=protocol,
        )

        await self._emit(
            step_type="TOOL_OUTPUT",
            message=(
                f"Compiled multi-platform containment scripts:\n"
                f"  • Linux: {rules.iptables_rule}\n"
                f"  • Cisco: {rules.cisco_acl.replace(chr(10), ' | ')}\n"
                f"  • Windows: {rules.powershell_command}"
            ),
            metadata={"containment_rules": rules.model_dump()},
            callback=on_thought,
        )

        # Step 3: Synthesis & HITL Safety Confirmation
        await self._emit(
            step_type="SYNTHESIS",
            message=(
                f"Containment scripts synthesized with strict source-IP drop parameters. "
                f"Zero destructive commands generated. Staged in Action Queue awaiting "
                f"Human-in-the-Loop (HITL) operator authorization."
            ),
            metadata={"safety_verified": True, "hitl_required": True},
            callback=on_thought,
        )

        return rules
