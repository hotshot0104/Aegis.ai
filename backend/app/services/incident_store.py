"""
In-Memory Incident and Audit Repository for Project AEGIS-AI.
Stores triaged IncidentCard instances, telemetry logs, and tamper-evident
cryptographic containment audit receipts in memory for sub-millisecond retrieval.
"""

import asyncio
from typing import List, Dict, Optional, Any
from backend.app.models.incident import IncidentCard


class IncidentStore:
    """Thread-safe in-memory repository for security incidents and containment audit logs."""

    def __init__(self) -> None:
        self._incidents: Dict[str, IncidentCard] = {}
        self._audit_logs: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def add_incident(self, incident: IncidentCard) -> None:
        """Stores a newly triaged incident card."""
        async with self._lock:
            self._incidents[incident.incident_id] = incident

    async def get_incident(self, incident_id: str) -> Optional[IncidentCard]:
        """Retrieves an incident card by its unique incident_id."""
        async with self._lock:
            return self._incidents.get(incident_id)

    async def get_all_incidents(self) -> List[IncidentCard]:
        """Returns all stored incidents ordered by most recent first."""
        async with self._lock:
            return list(reversed(list(self._incidents.values())))

    async def update_status(self, incident_id: str, new_status: str) -> Optional[IncidentCard]:
        """Updates the lifecycle status of an incident (e.g. CONTAINED, DISMISSED)."""
        async with self._lock:
            if incident_id in self._incidents:
                self._incidents[incident_id].status = new_status
                return self._incidents[incident_id]
            return None

    async def add_audit_log(self, audit_entry: Dict[str, Any]) -> None:
        """Appends a cryptographically signed containment audit receipt."""
        async with self._lock:
            self._audit_logs.append(audit_entry)

    async def get_audit_logs(self) -> List[Dict[str, Any]]:
        """Returns all cryptographic audit receipts."""
        async with self._lock:
            return list(reversed(self._audit_logs))

    async def clear(self) -> None:
        """Clears all stored incidents and logs (for testing resets)."""
        async with self._lock:
            self._incidents.clear()
            self._audit_logs.clear()


# Global IncidentStore singleton
incident_store = IncidentStore()
