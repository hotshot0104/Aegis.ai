"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { AgentThoughtEvent, IncidentCard } from "@/lib/api-client";

interface UseAgentWebSocketOptions {
  onThought?: (thought: AgentThoughtEvent) => void;
  onIncident?: (incident: IncidentCard) => void;
  onTelemetryTick?: (tickData: any) => void;
  onContainmentUpdate?: (containmentData: any) => void;
  enabled?: boolean;
}

export function useAgentWebSocket(options: UseAgentWebSocketOptions = {}) {
  const { onThought, onIncident, onTelemetryTick, onContainmentUpdate, enabled = true } = options;
  const [isConnected, setIsConnected] = useState(false);
  const [lastThought, setLastThought] = useState<AgentThoughtEvent | null>(null);
  const [lastIncident, setLastIncident] = useState<IncidentCard | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const onThoughtRef = useRef(onThought);
  onThoughtRef.current = onThought;

  const onIncidentRef = useRef(onIncident);
  onIncidentRef.current = onIncident;

  const onTelemetryTickRef = useRef(onTelemetryTick);
  onTelemetryTickRef.current = onTelemetryTick;

  const onContainmentUpdateRef = useRef(onContainmentUpdate);
  onContainmentUpdateRef.current = onContainmentUpdate;

  const connect = useCallback(() => {
    if (!enabled || typeof window === "undefined") return;

    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
    const fullWsEndpoint = `${wsUrl}/api/v1/ws/agent-thoughts`;

    try {
      const socket = new WebSocket(fullWsEndpoint);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsConnected(true);
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current);
          reconnectTimeoutRef.current = null;
        }

        // Setup ping/pong heartbeat every 20s
        pingIntervalRef.current = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ action: "PING" }));
          }
        }, 20000);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "AGENT_THOUGHT" && payload.data) {
            const thought = payload.data as AgentThoughtEvent;
            setLastThought(thought);
            if (onThoughtRef.current) {
              onThoughtRef.current(thought);
            }
          } else if ((payload.type === "INCIDENT_CREATED" || payload.type === "INCIDENT_UPDATE") && payload.data) {
            const incident = payload.data as IncidentCard;
            setLastIncident(incident);
            if (onIncidentRef.current) {
              onIncidentRef.current(incident);
            }
          } else if (payload.type === "TELEMETRY_TICK" && payload.data) {
            if (onTelemetryTickRef.current) {
              onTelemetryTickRef.current(payload.data);
            }
          } else if (payload.type === "CONTAINMENT_UPDATE" && payload.data) {
            if (onContainmentUpdateRef.current) {
              onContainmentUpdateRef.current(payload.data);
            }
          }
        } catch {
          // Ignore parse errors on raw messages
        }
      };

      socket.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        // Schedule reconnection in 3 seconds
        if (enabled) {
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, 3000);
        }
      };

      socket.onerror = () => {
        setIsConnected(false);
      };
    } catch {
      setIsConnected(false);
    }
  }, [enabled]);

  useEffect(() => {
    connect();

    return () => {
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return {
    isConnected,
    lastThought,
    lastIncident,
    reconnect: connect,
  };
}

