import { ChatProvider } from "@/components/agent-feed/chat-provider";
import { HomeAgentPanel } from "@/components/dashboard/home-agent-panel";
import { DashboardLeftPane } from "@/components/dashboard/left-pane";
import { MiddleApprovalsPanel } from "@/components/dashboard/middle-approvals-panel";
import { MiddleTerminal } from "@/components/dashboard/middle-terminal";

export default function DashboardPage() {
  const chatStorageScope = {
    userId: "soc-operator-01",
    workspaceId: "aegis-fleet-workspace",
  };

  return (
    <ChatProvider storageScope={chatStorageScope}>
      <div className="w-full h-full relative overflow-hidden bg-[#0A0A0C] flex p-2 gap-2">
        {/* Left Side Floating Glassy Panel */}
        <div className="w-[340px] h-full relative z-10 shrink-0 pointer-events-auto">
          <DashboardLeftPane />
        </div>

        {/* Middle Section — Upper 50% Workspace Terminal & Lower 50% Action Approvals Panel */}
        <div className="flex-1 h-full relative z-10 pointer-events-auto flex flex-col gap-2">
          {/* Upper Half (50% Height) — Okara Terminal */}
          <div className="h-1/2 w-full overflow-hidden">
            <MiddleTerminal />
          </div>

          {/* Lower Half (50% Height) — Action Approvals Panel */}
          <div className="h-1/2 w-full overflow-hidden">
            <MiddleApprovalsPanel />
          </div>
        </div>

        {/* Right Side Chat & Agent Panel */}
        <div className="w-[380px] h-full relative z-10 shrink-0 pointer-events-auto">
          <HomeAgentPanel />
        </div>
      </div>
    </ChatProvider>
  );
}
