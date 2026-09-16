"""
Rolling False-Positive Filter for Project AEGIS-AI.
Suppresses transient network noise, short bursts, and temporary spike events
using cumulative BDI score accumulation over a sliding window with noise-floor gating,
while maintaining consecutive anomaly tracking for low-and-slow / burst detection.
Escalates to the Multi-Agent Defense Core when sustained suspicion or streak thresholds are met.
Thread-safe for concurrent async access via asyncio.Lock.
"""

from typing import Dict, Tuple, Deque, Any, Optional
from collections import deque
import asyncio
import time


class RollingFalsePositiveFilter:
    """
    Temporal sliding window filter supporting both cumulative BDI score accumulation
    and consecutive anomaly streak tracking.
    
    In cumulative mode (when escalation_threshold is set), excess suspicion above
    the noise floor (max(0.0, bdi - noise_floor)) is summed over the sliding window.
    This enables detecting coordinated attack campaigns interleaved with normal noise.
    
    In streak mode (when escalation_threshold is None), escalation triggers when
    window_size consecutive flows are flagged anomalous.
    """

    def __init__(
        self,
        window_size: int = 5,
        escalation_threshold: Optional[float] = None,
        noise_floor: float = 0.20,
        time_window_seconds: float = 60.0
    ) -> None:
        """
        Args:
            window_size: Number of most recent events in the sliding window.
            escalation_threshold: Cumulative excess BDI threshold to trigger escalation.
                                  If None, falls back to requiring window_size consecutive anomalies.
            noise_floor: Normal baseline BDI threshold below which variance is treated as noise.
            time_window_seconds: Time horizon in seconds for history evaluation.
        """
        self.window_size = window_size
        self.escalation_threshold = escalation_threshold
        self.noise_floor = noise_floor
        self.time_window_seconds = time_window_seconds
        
        # ip -> deque of (timestamp, is_anomaly, bdi_score)
        self.history: Dict[str, Deque[Tuple[float, bool, float]]] = {}
        # ip -> consecutive anomaly count
        self.consecutive_streaks: Dict[str, int] = {}
        # Lazy async lock for thread-safe concurrent access from FastAPI handlers
        self._lock: Optional[asyncio.Lock] = None

    def evaluate(self, ip: str, is_anomaly: bool, bdi_score: float = 0.0) -> Dict[str, Any]:
        """
        Evaluates a new telemetry tick for a specific IP.
        
        Returns:
            Dict containing:
              - should_escalate: bool
              - consecutive_anomalies: int
              - cumulative_score: float
              - status: str
              - context metadata
        """
        now = time.time()

        if ip not in self.history:
            self.history[ip] = deque(maxlen=max(self.window_size * 2, 20))
            self.consecutive_streaks[ip] = 0

        ip_history = self.history[ip]

        # Purge outdated events beyond time window
        while ip_history and (now - ip_history[0][0] > self.time_window_seconds):
            ip_history.popleft()

        # Update consecutive anomaly streak
        if is_anomaly:
            self.consecutive_streaks[ip] = self.consecutive_streaks.get(ip, 0) + 1
        else:
            self.consecutive_streaks[ip] = 0
            
        consecutive_count = self.consecutive_streaks[ip]

        # Append current event
        ip_history.append((now, is_anomaly, bdi_score))

        # Calculate cumulative excess BDI above noise floor over most recent window_size events
        recent_events = list(ip_history)[-self.window_size:]
        cumulative_score = sum(max(0.0, bdi - self.noise_floor) for _, _, bdi in recent_events)

        # Determine escalation
        if self.escalation_threshold is not None:
            # Cumulative suspicion threshold or consecutive streak breach
            should_escalate = (
                cumulative_score >= self.escalation_threshold
                or consecutive_count >= self.window_size
            )
        else:
            # Pure consecutive streak mode (for unit tests / burst filter)
            should_escalate = consecutive_count >= self.window_size

        return {
            "ip": ip,
            "current_is_anomaly": is_anomaly,
            "current_bdi": bdi_score,
            "consecutive_anomalies": consecutive_count,
            "cumulative_score": round(cumulative_score, 4),
            "escalation_threshold": self.escalation_threshold,
            "window_events": len(recent_events),
            "window_size_max": self.window_size,
            "should_escalate": should_escalate,
            "status": "ESCALATE_TO_AGENT" if should_escalate else "BUFFERED_OR_FILTERED"
        }

    def reset_ip(self, ip: str) -> None:
        """Clears history for a specific IP (e.g. after containment)."""
        if ip in self.history:
            self.history[ip].clear()
        if ip in self.consecutive_streaks:
            self.consecutive_streaks[ip] = 0

    def clear_all(self) -> None:
        """Clears all tracking history."""
        self.history.clear()
        self.consecutive_streaks.clear()

    async def evaluate_async(self, ip: str, is_anomaly: bool, bdi_score: float = 0.0) -> Dict[str, Any]:
        """Thread-safe async wrapper around evaluate() for FastAPI concurrent access."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            return self.evaluate(ip, is_anomaly, bdi_score)
