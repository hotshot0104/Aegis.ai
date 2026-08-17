export const AGENT_CHAT_STORAGE_VERSION = 1;
export const LEGACY_AGENT_CHAT_SESSION_ID = "legacy-session";

export type AgentChatScope = {
  userId: string;
  workspaceId: string;
  sessionId?: string;
  personaId?: string;
};

export function buildAgentChatId(scope: AgentChatScope, sessionKey: string = "default"): string {
  const p = scope.personaId ? `:${scope.personaId}` : "";
  return `agent-chat:${scope.userId}:${scope.workspaceId}:${scope.sessionId || sessionKey}${p}`;
}

export function buildAgentChatStorageScope(
  scope?: AgentChatScope | string,
  sessionId?: string
): AgentChatScope & { sessionId: string } {
  if (typeof scope === "object" && scope !== null) {
    return {
      userId: scope.userId || "default-user",
      workspaceId: scope.workspaceId || "default-workspace",
      sessionId: sessionId || scope.sessionId || LEGACY_AGENT_CHAT_SESSION_ID,
      personaId: scope.personaId,
    };
  }

  return {
    userId: typeof scope === "string" ? scope : "default-user",
    workspaceId: "default-workspace",
    sessionId: sessionId || LEGACY_AGENT_CHAT_SESSION_ID,
  };
}

export function sanitizeAgentChatSessionId(sessionId: string | null | undefined): string | null {
  if (!sessionId) return null;
  return sessionId.replace(/[^a-zA-Z0-9_-]/g, "_");
}
