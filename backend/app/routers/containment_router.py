"""
Containment Execution Router for Project AEGIS-AI.
Enforces Rule 3 (Human-in-the-Loop Safety Gate).
Endpoints:
- POST /api/v1/agent/execute-containment: Authorizes and executes staged firewall isolation with officer token verification.
- GET /api/v1/agent/containment/audit-logs: Retrieves tamper-evident SHA-256 audit records.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.app.models.incident import ContainmentApprovalRequest, IncidentCard
from backend.app.core.config import settings
from backend.app.core.security import verify_officer_token, generate_audit_hash
from backend.app.core.websocket_manager import ws_manager
from backend.app.services.incident_store import incident_store
from backend.app.routers.telemetry_router import rolling_filter

router = APIRouter(prefix="/agent", tags=["Containment & Human-in-the-Loop (HITL)"])


class ContainmentExecutionResponse(BaseModel):
    """Response schema for authorized containment execution."""
    status: str  # CONTAINED | REJECTED
    incident_id: str
    action_taken: str
    platform: str
    executed_rule: str
    audit_hash: str
    authorized_by_token: str
    executed_at: str


@router.post("/execute-containment", response_model=ContainmentExecutionResponse, status_code=status.HTTP_200_OK)
async def execute_containment(request: ContainmentApprovalRequest) -> ContainmentExecutionResponse:
    """Enforces Human-in-the-Loop authorization for staged firewall isolation rules.
    
    1. Validates officer authentication token using constant-time string comparison.
    2. Updates incident status to CONTAINED.
    3. Computes a deterministic SHA-256 cryptographic audit digest for tamper evidence.
    4. Resets the attacker IP in the rolling filter.
    5. Broadcasts real-time containment confirmation to all connected SOC dashboards.
    """
    # Verify officer authorization token (Rule 3: HITL Safety Gate)
    if not verify_officer_token(request.officer_token, settings.OFFICER_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Invalid or missing SOC Officer Authorization Token. Containment execution aborted.",
        )

    # Look up target incident
    incident = await incident_store.get_incident(request.incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{request.incident_id}' not found.",
        )

    executed_at_iso = datetime.now(timezone.utc).isoformat()

    if request.approval_action.upper() == "REJECT":
        await incident_store.update_status(request.incident_id, "DISMISSED")
        audit_event = {
            "incident_id": request.incident_id,
            "action": "DISMISSED_BY_ANALYST",
            "attacker_ip": incident.attacker_ip,
            "platform": request.rule_type,
            "executed_at": executed_at_iso,
        }
        audit_hash = generate_audit_hash(audit_event)
        audit_event["audit_hash"] = audit_hash
        await incident_store.add_audit_log(audit_event)

        return ContainmentExecutionResponse(
            status="DISMISSED",
            incident_id=request.incident_id,
            action_taken="Incident dismissed by analyst",
            platform=request.rule_type,
            executed_rule="N/A",
            audit_hash=audit_hash,
            authorized_by_token="VERIFIED_OFFICER_TOKEN",
            executed_at=executed_at_iso,
        )

    # Resolve platform-specific firewall rule string
    rule_type = request.rule_type.lower()
    if rule_type == "cisco":
        applied_rule = incident.containment.cisco_acl if incident.containment else "N/A"
    elif rule_type == "powershell":
        applied_rule = incident.containment.powershell_command if incident.containment else "N/A"
    else:
        applied_rule = incident.containment.iptables_rule if incident.containment else "N/A"

    # Update incident state to CONTAINED
    await incident_store.update_status(request.incident_id, "CONTAINED")

    # Reset IP history in rolling filter so future normal flows are not blocked
    rolling_filter.reset_ip(incident.attacker_ip)

    # Generate cryptographic SHA-256 audit digest
    audit_event = {
        "incident_id": request.incident_id,
        "action": "FIREWALL_CONTAINMENT_APPLIED",
        "attacker_ip": incident.attacker_ip,
        "target_ip": incident.target_ip,
        "platform": rule_type,
        "applied_rule": applied_rule,
        "executed_at": executed_at_iso,
    }
    audit_hash = generate_audit_hash(audit_event)
    audit_event["audit_hash"] = audit_hash
    await incident_store.add_audit_log(audit_event)

    response_payload = {
        "status": "CONTAINED",
        "incident_id": request.incident_id,
        "action_taken": f"Source IP {incident.attacker_ip} isolated successfully",
        "platform": rule_type,
        "executed_rule": applied_rule,
        "audit_hash": audit_hash,
        "authorized_by_token": "VERIFIED_OFFICER_TOKEN",
        "executed_at": executed_at_iso,
    }

    # Broadcast containment confirmation to WebSocket clients
    await ws_manager.broadcast_containment(response_payload)

    return ContainmentExecutionResponse(**response_payload)


@router.get("/containment/audit-logs", response_model=List[Dict[str, Any]], status_code=status.HTTP_200_OK)
async def get_containment_audit_logs() -> List[Dict[str, Any]]:
    """Returns the immutable list of SHA-256 cryptographically hashed containment audit receipts."""
    return await incident_store.get_audit_logs()
