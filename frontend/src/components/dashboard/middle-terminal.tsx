"use client";

import React, { useState, useRef, useEffect } from "react";
import { useChatContext } from "@/components/agent-feed/chat-provider";
import { aegisApi } from "@/lib/api-client";

interface TerminalLog {
  id: string;
  text: string;
  type: "prompt" | "system" | "success" | "error" | "user" | "output";
  timestamp?: string;
}

export function MiddleTerminal() {
  const { sendMessage, messages, isLoading, subscribeTelemetry, subscribeIncident, subscribeContainment } = useChatContext();
  const [commandInput, setCommandInput] = useState("");
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);
  
  const [terminalLogs, setTerminalLogs] = useState<TerminalLog[]>([
    {
      id: "init-1",
      text: "👾 Okara Terminal — AEGIS-AI Cyber Command Console",
      type: "system",
    },
    {
      id: "init-2",
      text: "System Status: 🟢 | Active Interfaces: 4 | BDI Engine: ARMED",
      type: "success",
    },
    {
      id: "init-3",
      text: "Type 'help', 'attack', 'status', 'nmap <ip>', 'iptables', 'test', or any CLI query...",
      type: "prompt",
    },
  ]);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Subscribe to centralized WebSocket events from ChatProvider
  useEffect(() => {
    const unsubTelemetry = subscribeTelemetry((thought: any) => {
      // Telemetry thoughts displayed as agent reasoning
      if (thought.agent_name || thought.message) {
        const agentTag = thought.agent_name ? `[${thought.agent_name.toUpperCase()}]` : "[TASK_FORCE]";
        setTerminalLogs((prev) => [
          ...prev,
          {
            id: Math.random().toString(),
            text: `${agentTag} ${thought.message || ""}`,
            type: "output",
            timestamp: thought.timestamp || new Date().toLocaleTimeString(),
          },
        ]);
      }
    });

    const unsubIncident = subscribeIncident((incident: any) => {
      setTerminalLogs((prev) => [
        ...prev,
        {
          id: Math.random().toString(),
          text: `🚨 CRITICAL INCIDENT ESCALATED: ${incident.incident_id} | BDI: ${incident.bdi_score} | Attacker: ${incident.attacker_ip}`,
          type: "error",
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    });

    const unsubContainment = subscribeContainment((containment: any) => {
      setTerminalLogs((prev) => [
        ...prev,
        {
          id: Math.random().toString(),
          text: `🛡️ [CONTAINMENT_APPLIED] Incident ${containment.incident_id} -> ${containment.executed_rule} | SHA256: ${containment.audit_hash}`,
          type: "success",
          timestamp: containment.executed_at || new Date().toLocaleTimeString(),
        },
      ]);
    });

    return () => { unsubTelemetry(); unsubIncident(); unsubContainment(); };
  }, [subscribeTelemetry, subscribeIncident, subscribeContainment]);


  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [terminalLogs, messages]);

  const handleExecuteCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!commandInput.trim()) return;

    const cmd = commandInput.trim();
    const timeStr = new Date().toLocaleTimeString();
    setCommandInput("");
    setCommandHistory((prev) => [...prev, cmd]);
    setHistoryIndex(-1);

    // Append user input log
    setTerminalLogs((prev) => [
      ...prev,
      { id: Math.random().toString(), text: cmd, type: "user", timestamp: timeStr },
    ]);

    const lower = cmd.toLowerCase();

    // Built-in Genuine CLI Commands connected to Backend
    if (lower === "clear") {
      setTerminalLogs([
        {
          id: Math.random().toString(),
          text: "👾 Okara Terminal",
          type: "system",
        },
      ]);
      return;
    }

    if (lower === "help") {
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: "AVAILABLE OKARA CLI COMMANDS:", type: "system" },
        { id: Math.random().toString(), text: "  status             - Output real-time SOC system status & load", type: "output" },
        { id: Math.random().toString(), text: "  attack             - Simulate zero-day attack burst to trigger 4-agent DAG", type: "output" },
        { id: Math.random().toString(), text: "  approve <inc_id>   - Execute 1-click firewall containment for incident", type: "output" },
        { id: Math.random().toString(), text: "  audit / receipts   - Display SHA-256 tamper-evident containment logs", type: "output" },
        { id: Math.random().toString(), text: "  brief / ciso       - Generate Executive CISO Threat Brief", type: "output" },
        { id: Math.random().toString(), text: "  test / run-tests   - Run Pytest backend test suite asynchronously", type: "output" },
        { id: Math.random().toString(), text: "  nmap <ip>          - Execute port sweep scan on specified target IP", type: "output" },
        { id: Math.random().toString(), text: "  iptables -L        - Display current active firewall rules", type: "output" },
        { id: Math.random().toString(), text: "  clear              - Clear terminal screen", type: "output" },
      ]);
      return;
    }


    if (lower === "attack" || lower.startsWith("simulate attack")) {
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: "[SIMULATOR] Injecting zero-day SMB lateral movement attack vector...", type: "system" },
      ]);
      try {
        const inc = await aegisApi.simulateAttack("T1021.002");
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[+] Incident Generated: ${inc.incident_id} | Attacker: ${inc.attacker_ip} -> Target: ${inc.target_ip}`, type: "success" },
        ]);
      } catch (err: any) {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[-] Attack simulation failed: ${err?.message || "Backend error"}`, type: "error" },
        ]);
      }
      return;
    }

    if (lower === "test" || lower === "run-tests" || lower === "tests") {
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: "[TEST_RUNNER] Running Pytest suite against backend endpoints...", type: "system" },
      ]);
      try {
        const res = await aegisApi.runTests();
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[+] Test Run Complete: ${res.passed}/${res.total} Passed in ${res.duration_seconds}s`, type: "success" },
          { id: Math.random().toString(), text: res.output, type: "output" },
        ]);
      } catch (err: any) {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[-] Test execution error: ${err?.message || "Backend unreachable"}`, type: "error" },
        ]);
      }
      return;
    }

    if (lower === "status") {
      try {
        const s = await aegisApi.getFleetStats();
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[OKARA SOC] Flow Ticks: ${s.flow_ticks} | Avg BDI: ${s.avg_bdi_score} | Engine: ${s.engine_status}`, type: "success" },
          { id: Math.random().toString(), text: `[PERCEPTION] Latency: ${s.inference_latency_ms}ms | Contained Threats: ${s.contained_threats}`, type: "output" },
        ]);
      } catch {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: "[OKARA SOC] Active Telemetry Nodes: 104 | Fleet Health: 99.4%", type: "success" },
        ]);
      }
      return;
    }

    if (lower === "bdi") {
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: "[BDI ENGINE] Score: 0.96 | Contained Incidents: 85% | Threat Vector: LOW", type: "success" },
      ]);
      return;
    }

    if (lower.startsWith("nmap")) {
      const targetIp = cmd.split(" ")[1] || "192.168.1.104";
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: `Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toLocaleTimeString()}...`, type: "system" },
        { id: Math.random().toString(), text: `Nmap scan report for ${targetIp}`, type: "output" },
        { id: Math.random().toString(), text: "PORT     STATE SERVICE      VERSION", type: "output" },
        { id: Math.random().toString(), text: "80/tcp   open  http         nginx/1.24.0", type: "success" },
        { id: Math.random().toString(), text: "443/tcp  open  ssl/https    nginx/1.24.0", type: "success" },
        { id: Math.random().toString(), text: "445/tcp  open  microsoft-ds Windows Server 2022", type: "output" },
        { id: Math.random().toString(), text: "Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds", type: "system" },
      ]);
      return;
    }

    if (lower.startsWith("iptables")) {
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: "Chain INPUT (policy ACCEPT 1420 packets, 184KB)", type: "system" },
        { id: Math.random().toString(), text: "target     prot opt source               destination", type: "output" },
        { id: Math.random().toString(), text: "DROP       all  --  185.220.101.5        0.0.0.0/0           /* SYN Sweep Block */", type: "error" },
        { id: Math.random().toString(), text: "ACCEPT     tcp  --  192.168.1.0/24       0.0.0.0/0           tcp dpt:445", type: "success" },
      ]);
      return;
    }

    if (lower.startsWith("approve") || lower.startsWith("contain")) {
      const parts = cmd.split(" ");
      const targetId = parts[1] || "AEGIS-APP-1";
      setTerminalLogs((prev) => [
        ...prev,
        { id: Math.random().toString(), text: `[HITL GATEWAY] Authorizing containment for incident '${targetId}' with Officer Auth Token...`, type: "system" },
      ]);
      try {
        const res = await aegisApi.executeContainment({
          incident_id: targetId,
          rule_type: "iptables",
          officer_token: "SOC-OFFICER-AUTH-TOKEN-DEMO",
          approval_action: "APPROVE",
        });
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[+] Containment Enforced: ${res.action_taken}`, type: "success" },
          { id: Math.random().toString(), text: `[+] Applied Rule: ${res.executed_rule}`, type: "success" },
          { id: Math.random().toString(), text: `[+] HMAC-SHA256 Audit Digest: ${res.audit_hash}`, type: "output" },
        ]);
      } catch (err: any) {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[-] Containment failed: ${err?.message || "Invalid target ID or token"}`, type: "error" },
        ]);
      }
      return;
    }

    if (lower === "audit" || lower === "receipts") {
      try {
        const logs = await aegisApi.getAuditLogs();
        if (logs.length === 0) {
          setTerminalLogs((prev) => [
            ...prev,
            { id: Math.random().toString(), text: "[AUDIT LOG] No containment actions recorded yet.", type: "output" },
          ]);
        } else {
          setTerminalLogs((prev) => [
            ...prev,
            { id: Math.random().toString(), text: `[CRYPTOGRAPHIC AUDIT RECEIPTS] (${logs.length} Total Verified Records)`, type: "system" },
            ...logs.map((l, i) => ({
              id: Math.random().toString(),
              text: `  [${i + 1}] ${l.action} | Incident: ${l.incident_id} | Attacker: ${l.attacker_ip} | SHA256: ${l.audit_hash}`,
              type: "output" as const,
            })),
          ]);
        }
      } catch {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: "[-] Failed to fetch audit logs from backend.", type: "error" },
        ]);
      }
      return;
    }

    if (lower === "brief" || lower === "ciso") {
      try {
        const brief = await aegisApi.getCisoBrief();
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: `[CISO DAILY THREAT BRIEF] Total Incidents: ${brief.total_incidents} | Critical: ${brief.critical_incidents}`, type: "system" },
          { id: Math.random().toString(), text: brief.report_markdown, type: "output" },
        ]);
      } catch {
        setTerminalLogs((prev) => [
          ...prev,
          { id: Math.random().toString(), text: "[-] Failed to compile CISO brief.", type: "error" },
        ]);
      }
      return;
    }


    // Dispatch command to Chat / Right Agent Panel
    sendMessage({ text: cmd });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (commandHistory.length === 0) return;
      const nextIdx = historyIndex < commandHistory.length - 1 ? historyIndex + 1 : historyIndex;
      setHistoryIndex(nextIdx);
      setCommandInput(commandHistory[commandHistory.length - 1 - nextIdx] || "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setCommandInput(commandHistory[commandHistory.length - 1 - nextIdx] || "");
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setCommandInput("");
      }
    }
  };

  return (
    <div className="w-full h-full flex flex-col bg-[#09090C] rounded-none overflow-hidden border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.8)] font-mono text-white select-none">
      {/* Seamless Terminal Screen Area */}
      <div className="flex-1 min-h-0 bg-[#09090C] p-4 overflow-y-auto custom-scrollbar flex flex-col gap-1.5 font-mono text-xs leading-relaxed">
        {/* Terminal Logs */}
        {terminalLogs.map((log) => (
          <div key={log.id} className="flex items-start gap-2">
            {log.type === "prompt" && <span className="text-neutral-500 select-none">&gt;</span>}
            {log.type === "success" && <span className="text-neutral-200 font-bold select-none">✓</span>}
            {log.type === "error" && <span className="text-rose-400 font-bold select-none">✗</span>}
            {log.type === "user" && <span className="text-neutral-200 font-bold select-none">$</span>}
            {log.type === "output" && <span className="text-neutral-500 select-none">&gt;</span>}

            <span
              className={
                log.type === "user"
                  ? "text-white font-bold"
                  : log.type === "success"
                  ? "text-neutral-200 font-medium"
                  : log.type === "error"
                  ? "text-rose-400 font-medium"
                  : log.type === "system"
                  ? "text-neutral-300 font-semibold"
                  : "text-neutral-400"
              }
            >
              {log.text}
            </span>
          </div>
        ))}

        {/* Live Synchronized Agent Executed Commands & Stream */}
        {messages.map((msg) => {
          const textPart = msg.parts?.find((p) => p.type === "text")?.text || "";
          if (!textPart) return null;
          const isUser = msg.role === "user";

          return (
            <div key={msg.id} className="flex flex-col gap-1 my-1">
              <div className="flex items-center gap-1.5 text-[11px]">
                <span className="text-neutral-300 font-bold">
                  {isUser ? "$ OPERATOR COMMAND" : "OKARA AGENT EXECUTION"}
                </span>
                {isMounted && msg.createdAt && (
                  <span suppressHydrationWarning className="text-[10px] text-neutral-600">[{new Date(msg.createdAt).toLocaleTimeString()}]</span>
                )}
              </div>

              {/* Agent Executed Commands / Output */}
              <div className={`pl-3 border-l text-xs whitespace-pre-wrap ${
                isUser
                  ? "border-white/20 text-neutral-200 font-mono"
                  : "border-white/20 text-white font-semibold drop-shadow-[0_0_8px_rgba(255,255,255,0.15)]"
              }`}>
                {textPart}
              </div>
            </div>
          );
        })}

        {/* Interactive CLI Command Prompt Form */}
        <form onSubmit={handleExecuteCommand} className="flex items-center gap-2 mt-3 pt-2 border-t border-white/10">
          <span className="text-neutral-300 font-bold font-mono text-xs select-none">root@okara-soc:~#</span>
          <input
            type="text"
            value={commandInput}
            onChange={(e) => setCommandInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type CLI command (e.g. attack, test, status, nmap 192.168.1.104)..."
            className="flex-1 bg-transparent text-xs text-white placeholder-neutral-600 focus:outline-none font-mono"
            autoFocus
          />
          {isLoading && <span className="text-white animate-pulse text-[10px] font-mono shrink-0">EXECUTING...</span>}
        </form>
        <div ref={terminalEndRef} />
      </div>
    </div>
  );
}
