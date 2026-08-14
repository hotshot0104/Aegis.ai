"""
Rolling False-Positive Filter for Project AEGIS-AI.
Suppresses transient network noise, short bursts, and temporary spike events
by requiring K consecutive anomaly ticks per IP within a sliding time window
before escalating to the Multi-Agent Defense Core.
Thread-safe for concurrent async access via asyncio.Lock.
"""

from typing import Dict, Tuple, Deque, Any, Optional
from collections import deque
import asyncio
import time


class RollingFalsePositiveFilter:
    """
    Temporal sliding window filter to ensure sustained compromise behavior
    before triggering autonomous multi-agent defense.
    """

    def __init__(
        self,
        window_size: int = 3,
        time_window_seconds: float = 5.0
    ) -> None:
        """
        Args:
            window_size: Number of consecutive anomalies required (K=3).
            time_window_seconds: Time horizon in seconds for history evaluation.
        """
        self.window_size = window_size
        self.time_window_seconds = time_window_seconds
        # ip -> deque of (timestamp, is_anomaly, bdi_score)
        self.history: Dict[str, Deque[Tuple[float, bool, float]]] = {}
        # Lazy async lock for thread-safe concurrent access from FastAPI handlers
        self._lock: Optional[asyncio.Lock] = None

    def evaluate(self, ip: str, is_anomaly: bool, bdi_score: float = 0.0) -> Dict[str, Any]:
        """
        Evaluates a new telemetry tick for a specific IP.
        
        Returns:
            Dict with should_escalate, consecutive_anomalies_count, and history.
        """
        now = time.time()

        if ip not in self.history:
            self.history[ip] = deque(maxlen=self.window_size * 2)

        ip_history = self.history[ip]

        # Purge outdated events beyond time window
        while ip_history and (now - ip_history[0][0] > self.time_window_seconds):
            ip_history.popleft()

        # Append current event
        ip_history.append((now, is_anomaly, bdi_score))

        # Check if the most recent K events are all verified anomalies
        recent_events = list(ip_history)[-self.window_size:]
        consecutive_anomalies = 0

        for _, flag, _ in reversed(recent_events):
            if flag:
                consecutive_anomalies += 1
            else:
                break

        should_escalate = (
            len(recent_events) >= self.window_size
            and all(flag for _, flag, _ in recent_events)
        )

        return {
            "ip": ip,
            "current_is_anomaly": is_anomaly,
            "current_bdi": bdi_score,
            "consecutive_anomalies": consecutive_anomalies,
            "window_size_required": self.window_size,
            "should_escalate": should_escalate,
            "status": "ESCALATE_TO_AGENT" if should_escalate else "BUFFERED_OR_FILTERED"
        }

    def reset_ip(self, ip: str) -> None:
        """Clears history for a specific IP (e.g. after containment)."""
        if ip in self.history:
            self.history[ip].clear()

    def clear_all(self) -> None:
        """Clears all tracking history."""
        self.history.clear()

    async def evaluate_async(self, ip: str, is_anomaly: bool, bdi_score: float = 0.0) -> Dict[str, Any]:
        """Thread-safe async wrapper around evaluate() for FastAPI concurrent access."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            return self.evaluate(ip, is_anomaly, bdi_score)
