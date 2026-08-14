"""
Autonomous Agent Router for Project AEGIS-AI.
Endpoints:
- POST /api/v1/agent/investigate: Trigger manual multi-agent triage on demand.
- GET /api/v1/agent/daily-brief: Retrieve structured Executive CISO Daily Threat Brief.
- GET /api/v1/agent/incidents: List all triaged incident cards.
- GET /api/v1/agent/incidents/{incident_id}: Get specific incident card details.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.models.incident import IncidentCard
from backend.app.core.websocket_manager import ws_manager
from backend.app.services.incident_store import incident_store
from backend.app.services.agent_supervisor import AgentSupervisor

router = APIRouter(prefix="/agent", tags=["Autonomous Agent Defense Core"])
agent_supervisor = AgentSupervisor()


class ManualInvestigationRequest(BaseModel):
    """Request schema for manually triggering agentic triage on a flow."""
    flow_data: Dict[str, Any] = Field(description="Flow feature dictionary")
    bdi_score: float = Field(default=0.92, ge=0.0, le=1.0, description="Behavioral Deviation Index score")


class CisoBriefResponse(BaseModel):
    """Response schema for the CISO executive daily brief."""
    report_markdown: str
    total_incidents: int
    critical_incidents: int
    generated_at: str


@router.post("/investigate", response_model=IncidentCard, status_code=status.HTTP_200_OK)
async def investigate_flow(request: ManualInvestigationRequest) -> IncidentCard:
    """Dispatches the 4-Agent Autonomous Reasoning DAG for a specific flow payload,
    streams intermediate thoughts over WebSockets, and returns the synthesized IncidentCard.
    """
    incident_card = await agent_supervisor.triage_incident(
        flow_data=request.flow_data,
        bdi_score=request.bdi_score,
        on_thought=ws_manager.broadcast_thought,
    )

    await incident_store.add_incident(incident_card)
    await ws_manager.broadcast_json({
        "type": "INCIDENT_CREATED",
        "data": incident_card.model_dump(mode="json"),
    })

    return incident_card


@router.get("/daily-brief", response_model=CisoBriefResponse, status_code=status.HTTP_200_OK)
async def get_ciso_daily_brief() -> CisoBriefResponse:
    """Generates and returns the GitHub-flavored Markdown Executive CISO Daily Threat Brief
    compiled autonomously from all triaged and contained incidents.
    """
    incidents = await incident_store.get_all_incidents()
    report_md = agent_supervisor.generate_ciso_daily_brief(incidents)

    critical_count = sum(
        1 for inc in incidents if inc.asset and inc.asset.criticality_level == "CRITICAL_TIER_1"
    )

    from datetime import datetime, timezone
    return CisoBriefResponse(
        report_markdown=report_md,
        total_incidents=len(incidents),
        critical_incidents=critical_count,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/incidents", response_model=List[IncidentCard], status_code=status.HTTP_200_OK)
async def list_incidents() -> List[IncidentCard]:
    """Returns the list of all triaged incident cards in reverse chronological order."""
    return await incident_store.get_all_incidents()


@router.get("/incidents/{incident_id}", response_model=IncidentCard, status_code=status.HTTP_200_OK)
async def get_incident(incident_id: str) -> IncidentCard:
    """Retrieves a specific incident card by its incident_id."""
    incident = await incident_store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return incident
