"""
Deterministic Cyber Security Tools for Project AEGIS-AI.
These are the structured Python tools that agents invoke via the DAG.
All tools use strict Pydantic-validated inputs/outputs (Rule 4).
No arbitrary shell execution. No IoC lookups (Rule 1).
"""

import json
import ipaddress
import os
from typing import Dict, Any, List, Optional

from backend.app.models.incident import (
    AssetProfile,
    MitreMapping,
    ContainmentRules,
)

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data"
)


class CyberTools:
    """Deterministic, schema-validated security tools for the AEGIS-AI agent core."""

    # Class-level caches to avoid disk I/O on every tool call
    _asset_registry_cache: Optional[Dict] = None
    _mitre_kb_cache: Optional[List[Dict]] = None

    # ──────────────────────────────────────────────────────────────────────
    # Tool 1: Flow Metrics Deep Inspector
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def tool_inspect_flow_metrics(flow_data: Dict[str, Any], bdi_score: float) -> str:
        """Performs deep statistical inspection of non-payload flow metrics.

        Analyzes burst rates, SYN/ACK ratios, byte symmetry, port dispersion,
        and subnet traversal patterns to produce a human-readable narrative.

        Args:
            flow_data: Raw flow dictionary with statistical features.
            bdi_score: The Behavioral Deviation Index score from the ML engine.

        Returns:
            Human-readable flow analysis narrative string.
        """
        src_ip = flow_data.get("src_ip", "UNKNOWN")
        dst_ip = flow_data.get("dst_ip", "UNKNOWN")
        dst_port = flow_data.get("dst_port", 0)
        protocol = flow_data.get("protocol_type", "tcp").upper()

        count = flow_data.get("count", 0)
        srv_count = flow_data.get("srv_count", 0)
        same_srv_rate = flow_data.get("same_srv_rate", 0.0)
        diff_srv_rate = flow_data.get("diff_srv_rate", 0.0)
        serror_rate = flow_data.get("serror_rate", 0.0)
        src_bytes = flow_data.get("src_bytes", 0)
        dst_bytes = flow_data.get("dst_bytes", 0)
        duration = flow_data.get("duration", 0.0)
        srv_diff_host_rate = flow_data.get("srv_diff_host_rate", 0.0)
        dst_host_srv_diff_host_rate = flow_data.get("dst_host_srv_diff_host_rate", 0.0)
        flag = flow_data.get("flag", "SF")

        # Compute dynamic severity label from BDI score
        severity = "CRITICAL" if bdi_score >= 0.80 else "SUSPICIOUS" if bdi_score >= 0.50 else "NOMINAL"
        findings = []
        findings.append(
            f"Flow Analysis: {src_ip} -> {dst_ip}:{dst_port} ({protocol}). "
            f"BDI Score: {bdi_score:.4f} ({severity})."
        )

        if count > 100:
            findings.append(
                f"Connection burst rate is {count} req/window (enterprise baseline ~12 req/window). "
                f"This indicates potential flood or lateral sweep behavior."
            )

        if diff_srv_rate > 0.7:
            findings.append(
                f"High service dispersion: diff_srv_rate={diff_srv_rate:.2f} — "
                f"indicative of stealthy multi-port reconnaissance."
            )

        if serror_rate > 0.5:
            findings.append(
                f"Elevated SYN error rate: serror_rate={serror_rate:.2f} — "
                f"characteristic of SYN-flood or half-open port scanning."
            )

        if src_bytes > 0 and dst_bytes == 0:
            findings.append(
                "Asymmetric byte profile: high outbound, zero inbound — "
                "potential data exfiltration pattern."
            )
        elif src_bytes > 0 and dst_bytes > 0 and abs(src_bytes - dst_bytes) < 10:
            findings.append(
                f"Rigid byte symmetry: src={src_bytes}, dst={dst_bytes} — "
                "characteristic of C2 beaconing heartbeat."
            )

        if dst_host_srv_diff_host_rate > 0.7:
            findings.append(
                f"Cross-subnet lateral traversal: dst_host_srv_diff_host_rate="
                f"{dst_host_srv_diff_host_rate:.2f} — host is probing multiple subnets."
            )

        if flag == "S0":
            findings.append(
                "TCP flag S0 detected (half-open SYN without ACK reply) — "
                "connection attempt with no successful handshake."
            )

        return " | ".join(findings)

    # ──────────────────────────────────────────────────────────────────────
    # Tool 2: Asset & Topology Registry Query
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def tool_query_asset_registry(ip: str) -> AssetProfile:
        """Queries the internal subnet asset registry to determine host identity,
        department ownership, criticality tier, and crown-jewel status.

        Args:
            ip: IP address string to look up.

        Returns:
            AssetProfile Pydantic model with full host metadata.
        """
        asset_path = os.path.join(DATA_DIR, "asset_inventory.json")

        # Use cached registry to avoid disk I/O on every call
        if CyberTools._asset_registry_cache is None:
            try:
                with open(asset_path, "r", encoding="utf-8") as f:
                    CyberTools._asset_registry_cache = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                CyberTools._asset_registry_cache = {}

        registry = CyberTools._asset_registry_cache

        if ip in registry:
            return AssetProfile(**registry[ip])

        # Fallback for unknown hosts
        return AssetProfile(
            ip=ip,
            hostname=f"NODE-{ip.replace('.', '-')}",
            owner_department="Unknown Subnet",
            criticality_level="MEDIUM",
            os_type="Linux Generic",
            mac_address="UNKNOWN",
            subnet="UNKNOWN",
            crown_jewel=False,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Tool 3: MITRE ATT&CK Vector Search
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def tool_mitre_vector_search(
        flow_data: Dict[str, Any],
    ) -> MitreMapping:
        """Searches the local MITRE ATT&CK knowledge base by matching
        statistical flow indicators against known technique signatures.

        This is a behavioral pattern match, NOT an IoC signature lookup.
        It maps observed statistical deviations to known adversary TTPs.

        Args:
            flow_data: Raw flow dictionary with statistical features.

        Returns:
            MitreMapping Pydantic model with the best-matched technique.
        """
        mitre_path = os.path.join(DATA_DIR, "mitre_attack_kb.json")

        # Use cached knowledge base to avoid disk I/O on every call
        if CyberTools._mitre_kb_cache is None:
            try:
                with open(mitre_path, "r", encoding="utf-8") as f:
                    CyberTools._mitre_kb_cache = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                CyberTools._mitre_kb_cache = []

        kb: List[Dict] = CyberTools._mitre_kb_cache

        # Extract behavioral signals from the flow
        dst_port = flow_data.get("dst_port", 0)
        service = str(flow_data.get("service", "")).lower()
        diff_srv_rate = float(flow_data.get("diff_srv_rate", 0.0))
        serror_rate = float(flow_data.get("serror_rate", 0.0))
        same_srv_rate = float(flow_data.get("same_srv_rate", 0.0))
        srv_diff_host_rate = float(flow_data.get("srv_diff_host_rate", 0.0))
        dst_host_srv_diff_host_rate = float(flow_data.get("dst_host_srv_diff_host_rate", 0.0))
        src_bytes = float(flow_data.get("src_bytes", 0))
        dst_bytes = float(flow_data.get("dst_bytes", 0))
        count = float(flow_data.get("count", 0))
        flag = str(flow_data.get("flag", "SF")).upper()

        # Score each technique by indicator overlap
        best_match: Optional[Dict] = None
        best_score: float = 0.0
        best_indicators: List[str] = []

        for technique in kb:
            score = 0.0
            matched_indicators = []

            if technique["technique_id"] == "T1021.002":
                # Lateral Movement via SMB
                if dst_port == 445 or service == "smb":
                    score += 40.0
                    matched_indicators.append("port 445 / SMB service")
                if same_srv_rate > 0.8:
                    score += 20.0
                    matched_indicators.append(f"same_srv_rate={same_srv_rate:.2f}")
                if dst_host_srv_diff_host_rate > 0.5:
                    score += 25.0
                    matched_indicators.append(f"cross-subnet traversal={dst_host_srv_diff_host_rate:.2f}")
                if count > 100:
                    score += 15.0
                    matched_indicators.append(f"high burst count={int(count)}")

            elif technique["technique_id"] == "T1046":
                # Network Service Discovery / Port Scan
                if diff_srv_rate > 0.7:
                    score += 35.0
                    matched_indicators.append(f"high diff_srv_rate={diff_srv_rate:.2f}")
                if flag == "S0":
                    score += 30.0
                    matched_indicators.append("S0 half-open SYN flag")
                if serror_rate > 0.5:
                    score += 20.0
                    matched_indicators.append(f"serror_rate={serror_rate:.2f}")
                if count > 200:
                    score += 15.0
                    matched_indicators.append(f"rapid multi-port probe count={int(count)}")

            elif technique["technique_id"] == "T1071.001":
                # C2 Beaconing
                if src_bytes > 0 and dst_bytes > 0 and abs(src_bytes - dst_bytes) < 20:
                    score += 40.0
                    matched_indicators.append(f"byte symmetry src={int(src_bytes)} dst={int(dst_bytes)}")
                if same_srv_rate > 0.95:
                    score += 25.0
                    matched_indicators.append(f"single-service rate={same_srv_rate:.2f}")
                if srv_diff_host_rate < 0.05:
                    score += 20.0
                    matched_indicators.append("zero host dispersion (single C2 target)")
                if count > 50 and count < 500:
                    score += 15.0
                    matched_indicators.append(f"periodic beacon count={int(count)}")

            elif technique["technique_id"] == "T1048":
                # Data Exfiltration
                if src_bytes > 10000 and dst_bytes < 100:
                    score += 45.0
                    matched_indicators.append(f"extreme byte asymmetry src={int(src_bytes)} dst={int(dst_bytes)}")
                if diff_srv_rate > 0.3:
                    score += 20.0
                    matched_indicators.append(f"alternative protocol dispersion={diff_srv_rate:.2f}")
                if count > 50:
                    score += 15.0
                    matched_indicators.append(f"sustained exfil burst count={int(count)}")

            if score > best_score:
                best_score = score
                best_match = technique
                best_indicators = matched_indicators

        # Fallback if no match found
        if best_match is None or best_score < 10.0:
            return MitreMapping(
                technique_id="UNKNOWN",
                technique_name="Unclassified Behavioral Anomaly",
                tactic="Unknown",
                description="Flow exhibits statistical anomaly but does not match known MITRE ATT&CK behavioral patterns.",
                confidence=round(min(best_score, 100.0), 1),
                indicators_matched=best_indicators,
                mitigation="Investigate manually. Consider isolating the source host pending analysis.",
            )

        return MitreMapping(
            technique_id=best_match["technique_id"],
            technique_name=best_match["technique_name"],
            tactic=best_match["tactic"],
            description=best_match["description"],
            confidence=round(min(best_score, 100.0), 1),
            indicators_matched=best_indicators,
            mitigation=best_match.get("mitigation", ""),
        )

    # ──────────────────────────────────────────────────────────────────────
    # Tool 4: Containment Rule Generator
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def tool_generate_containment_command(
        src_ip: str, dst_port: int, protocol: str = "tcp"
    ) -> ContainmentRules:
        """Generates exact CLI scripts for instant network isolation across
        multiple firewall platforms (Linux iptables, Cisco IOS ACL, Windows PowerShell).

        Safety: Generates ONLY precise source-IP drop rules.
        Never generates destructive commands (rm, reboot, flush-all).

        Args:
            src_ip: Attacking source IP address.
            dst_port: Target destination port.
            protocol: Protocol type (tcp/udp/icmp).

        Returns:
            ContainmentRules Pydantic model with platform-specific commands.
        """
        # Validate IP address format (prevents injection of non-IP strings)
        try:
            validated_ip = str(ipaddress.ip_address(src_ip.strip()))
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{src_ip}'")

        safe_ip = validated_ip
        safe_port = int(dst_port)
        safe_proto = protocol.lower().replace(";", "")

        return ContainmentRules(
            iptables_rule=(
                f"sudo iptables -I INPUT 1 -s {safe_ip} -p {safe_proto} "
                f"--dport {safe_port} -j DROP && "
                f"sudo iptables -I INPUT 2 -s {safe_ip} -j DROP"
            ),
            cisco_acl=(
                f"access-list 101 deny {safe_proto} host {safe_ip} any eq {safe_port}\n"
                f"access-list 101 deny ip host {safe_ip} any"
            ),
            powershell_command=(
                f"New-NetFirewallRule -DisplayName 'AEGIS-Block-{safe_ip}' "
                f"-Direction Inbound -RemoteAddress '{safe_ip}' "
                f"-Protocol {safe_proto.upper()} -LocalPort {safe_port} -Action Block"
            ),
        )
