"use client";

import * as React from "react";
import {
  aegisApi,
  type AgentThoughtEvent,
  type IncidentCard,
  type ChatCommandResponse,
  type ContainmentApprovalResponse,
} from "@/lib/api-client";
import { useAgentWebSocket } from "@/hooks/use-agent-websocket";

export type MessagePart = {
  type: string;
  text?: string;
  toolCallId?: string;
  toolName?: string;
  state?: "input-streaming" | "input-available" | "output-available" | "output-error" | string;
  input?: any;
  output?: any;
  errorText?: string;
};

export type UIMessage = {
  id: string;
  role: "user" | "assistant" | "system";
  parts: MessagePart[];
  createdAt?: Date;
  incidentId?: string;
};

type TelemetrySubscriber = (tick: any) => void;
type IncidentSubscriber = (incident: IncidentCard) => void;
type ContainmentSubscriber = (data: any) => void;

type ChatContextType = {
  messages: UIMessage[];
  sendMessage: (params: { text: string }) => Promise<void>;
  isLoading: boolean;
  status: "ready" | "submitted" | "streaming" | "error";
  hydrationStatus: "idle" | "loading" | "restored" | "empty";
  error: Error | null;
  addAgentThought: (event: AgentThoughtEvent) => void;
  resetActiveThread: () => void;
  isWsConnected: boolean;
  executeContainment: (incidentId: string, ruleType?: string) => Promise<ContainmentApprovalResponse>;
  dismissIncident: (incidentId: string, reason?: string) => Promise<void>;
  subscribeTelemetry: (cb: TelemetrySubscriber) => () => void;
  subscribeIncident: (cb: IncidentSubscriber) => () => void;
  subscribeContainment: (cb: ContainmentSubscriber) => () => void;
};

const ChatContext = React.createContext<ChatContextType | undefined>(undefined);

export function ChatProvider({
  children,
  storageScope,
}: {
  children: React.ReactNode;
  storageScope?: any;
}) {
  const [messages, setMessages] = React.useState<UIMessage[]>([
    {
      id: "initial-assistant-1",
      role: "assistant",
      parts: [
        {
          type: "reasoning",
          text: "[Supervisor Agent] Initializing Autonomous SOC Fleet Monitor...",
        },
        {
          type: "tool-tool_inspect_flow_metrics",
          toolName: "tool_inspect_flow_metrics",
          toolCallId: "call-init-01",
          state: "output-available",
          input: { src_ip: "185.220.101.5", target: "Finance Subnet (192.168.1.104)" },
          output: { bdi_score: 0.96, rate: "1,240 SYN/s", anomaly: true },
        },
        {
          type: "reasoning",
          text: "[ThreatHunter Agent] Delegating vector analysis to MITRE ATT&CK correlation engine...",
        },
        {
          type: "tool-threat_hunter_investigate",
          toolName: "threat_hunter_investigate",
          toolCallId: "call-init-02",
          state: "output-available",
          input: { technique: "T1046 Network Service Discovery" },
          output: { confidence: 0.96, severity: "HIGH_RISK" },
        },
        {
          type: "text",
          text: "### 🛡️ AEGIS Multi-Agent System Active\nMonitoring 104 network nodes. Detected high-velocity SYN sweep from **185.220.101.5** targeting Finance Subnet.",
        },
      ],
    },
  ]);
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const [status, setStatus] = React.useState<"ready" | "submitted" | "streaming" | "error">("ready");
  const [error, setError] = React.useState<Error | null>(null);

  const activeAssistantMsgIdRef = React.useRef<string | null>(null);

  // Incoming thought dispatcher from WebSocket
  const handleIncomingThought = React.useCallback((event: AgentThoughtEvent) => {
    setMessages((prev) => {
      const activeId = activeAssistantMsgIdRef.current;
      if (!activeId) {
        // Create an unattached assistant message if none is active
        const newMsgId = `assistant-ws-${Date.now()}`;
        activeAssistantMsgIdRef.current = newMsgId;
        const newPart: MessagePart = {
          type: "reasoning",
          text: `[${event.agent_name}] ${event.message}`,
        };
        return [
          ...prev,
          {
            id: newMsgId,
            role: "assistant",
            parts: [newPart],
            createdAt: new Date(),
          },
        ];
      }

      return prev.map((msg) => {
        if (msg.id !== activeId) return msg;

        const updatedParts = [...msg.parts];

        if (event.step_type === "TOOL_CALL") {
          const tool = (event.metadata?.tool as string) || "tool_inspect_flow_metrics";
          updatedParts.push({
            type: `tool-${tool}`,
            toolName: tool,
            toolCallId: `call-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            state: "input-available",
            input: event.metadata || {},
          });
        } else if (event.step_type === "TOOL_OUTPUT") {
          // Find the last matching tool part and mark output available
          let found = false;
          for (let i = updatedParts.length - 1; i >= 0; i--) {
            const p = updatedParts[i] as any;
            if (p.type && (p.type.startsWith("tool-") || p.toolName) && p.state !== "output-available") {
              p.state = "output-available";
              p.output = event.metadata || { output: event.message };
              found = true;
              break;
            }
          }
          if (!found) {
            updatedParts.push({
              type: "reasoning",
              text: `✓ ${event.message}`,
            });
          }
        } else {
          // THOUGHT or SYNTHESIS
          updatedParts.push({
            type: "reasoning",
            text: event.message,
          });
        }

        return { ...msg, parts: updatedParts };
      });
    });
  }, []);

  const handleIncomingIncident = React.useCallback((incident: IncidentCard) => {
    // Notify all incident subscribers
    incidentSubscribersRef.current.forEach((cb) => cb(incident));
  }, []);

  const handleTelemetryTick = React.useCallback((tick: any) => {
    telemetrySubscribersRef.current.forEach((cb) => cb(tick));
  }, []);

  const handleContainmentUpdate = React.useCallback((data: any) => {
    containmentSubscribersRef.current.forEach((cb) => cb(data));
  }, []);

  // Subscriber registries
  const telemetrySubscribersRef = React.useRef<Set<TelemetrySubscriber>>(new Set());
  const incidentSubscribersRef = React.useRef<Set<IncidentSubscriber>>(new Set());
  const containmentSubscribersRef = React.useRef<Set<ContainmentSubscriber>>(new Set());

  const subscribeTelemetry = React.useCallback((cb: TelemetrySubscriber) => {
    telemetrySubscribersRef.current.add(cb);
    return () => { telemetrySubscribersRef.current.delete(cb); };
  }, []);

  const subscribeIncident = React.useCallback((cb: IncidentSubscriber) => {
    incidentSubscribersRef.current.add(cb);
    return () => { incidentSubscribersRef.current.delete(cb); };
  }, []);

  const subscribeContainment = React.useCallback((cb: ContainmentSubscriber) => {
    containmentSubscribersRef.current.add(cb);
    return () => { containmentSubscribersRef.current.delete(cb); };
  }, []);

  const { isConnected: isWsConnected } = useAgentWebSocket({
    onThought: handleIncomingThought,
    onIncident: handleIncomingIncident,
    onTelemetryTick: handleTelemetryTick,
    onContainmentUpdate: handleContainmentUpdate,
  });

  const resetActiveThread = React.useCallback(() => {
    setMessages([]);
    setIsLoading(false);
    setStatus("ready");
    setError(null);
    activeAssistantMsgIdRef.current = null;
  }, []);

  const sendMessage = React.useCallback(
    async ({ text }: { text: string }) => {
      if (!text.trim() || isLoading) return;

      const userMsgId = `user-${Date.now()}`;
      const assistantMsgId = `assistant-${Date.now() + 1}`;
      activeAssistantMsgIdRef.current = assistantMsgId;

      const userMsg: UIMessage = {
        id: userMsgId,
        role: "user",
        parts: [{ type: "text", text }],
        createdAt: new Date(),
      };

      const initialAssistantMsg: UIMessage = {
        id: assistantMsgId,
        role: "assistant",
        parts: [],
        createdAt: new Date(),
      };

      setMessages((prev) => [...prev, userMsg, initialAssistantMsg]);
      setIsLoading(true);
      setStatus("streaming");
      setError(null);

      try {
        const response: ChatCommandResponse = await aegisApi.sendChatMessage(text);

        setMessages((prev) =>
          prev.map((msg) => {
            if (msg.id !== assistantMsgId) return msg;

            const finalParts: MessagePart[] = [...msg.parts];

            // If incident was triaged, ensure structured outputs are present
            if (response.incident) {
              const inc = response.incident;

              // Append final markdown response
              finalParts.push({
                type: "text",
                text: response.message,
              });

              return {
                ...msg,
                parts: finalParts,
                incidentId: inc.incident_id,
              };
            }

            // Standard response
            finalParts.push({
              type: "text",
              text: response.message || "Command executed successfully.",
            });

            return { ...msg, parts: finalParts };
          })
        );

        setStatus("ready");
      } catch (err: any) {
        console.error("[AEGIS ChatProvider] Error sending message:", err);
        const fallbackErrorMsg = err?.message || "Failed to reach AEGIS-AI backend on port 8000.";
        setError(new Error(fallbackErrorMsg));
        setStatus("error");

        // Provide informative fallback text in the message
        setMessages((prev) =>
          prev.map((msg) => {
            if (msg.id !== assistantMsgId) return msg;
            return {
              ...msg,
              parts: [
                ...msg.parts,
                {
                  type: "text",
                  text: `⚠️ **Connection Notice**: ${fallbackErrorMsg}\n\nPlease ensure the Python FastAPI backend is running on \`http://localhost:8000\`.`,
                },
              ],
            };
          })
        );
      } finally {
        setIsLoading(false);
        activeAssistantMsgIdRef.current = null;
      }
    },
    [isLoading]
  );

  const addAgentThought = React.useCallback((event: AgentThoughtEvent) => {
    handleIncomingThought(event);
  }, [handleIncomingThought]);

  const executeContainment = React.useCallback(
    async (incidentId: string, ruleType = "iptables") => {
      const res = await aegisApi.executeContainment({
        incident_id: incidentId,
        rule_type: ruleType,
      });

      // Add audit feedback message to active chat
      setMessages((prev) => [
        ...prev,
        {
          id: `containment-${Date.now()}`,
          role: "assistant",
          parts: [
            {
              type: "text",
              text: (
                `🛡️ **Containment Verified & Enforced** for Incident \`${incidentId}\`:\n\n` +
                `\`\`\`text\n${res.execution_log}\n\`\`\`\n` +
                `> **HMAC-SHA256 Audit Signature**: \`${res.audit_record.hmac_sha256_signature}\`\n` +
                `> **Status**: \`${res.status}\``
              ),
            },
          ],
          createdAt: new Date(),
        },
      ]);

      return res;
    },
    []
  );

  const dismissIncident = React.useCallback(
    async (incidentId: string, reason = "False Positive / Whitelisted Activity") => {
      await aegisApi.dismissIncident(incidentId, reason);
      setMessages((prev) => [
        ...prev,
        {
          id: `dismiss-${Date.now()}`,
          role: "assistant",
          parts: [
            {
              type: "text",
              text: `Incident \`${incidentId}\` has been dismissed. Reason: *${reason}*.`,
            },
          ],
          createdAt: new Date(),
        },
      ]);
    },
    []
  );

  return (
    <ChatContext.Provider
      value={{
        messages,
        sendMessage,
        isLoading,
        status,
        hydrationStatus: "restored",
        error,
        addAgentThought,
        resetActiveThread,
        isWsConnected,
        executeContainment,
        dismissIncident,
        subscribeTelemetry,
        subscribeIncident,
        subscribeContainment,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
}

export function useChatContext() {
  const ctx = React.useContext(ChatContext);
  if (!ctx) {
    throw new Error("useChatContext must be used within a ChatProvider");
  }
  return ctx;
}
