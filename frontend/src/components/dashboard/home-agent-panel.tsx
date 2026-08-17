"use client";

import React, { useState, useEffect } from "react";
import { useChatContext } from "@/components/agent-feed/chat-provider";
import { AgentFeed } from "@/components/agent-feed/agent-feed";
import { aegisApi } from "@/lib/api-client";
import {
  Plus,
  ArrowUp,
  History,
  Trash2,
  Search,
  MessageSquare,
  Minus,
  Bot,
  Play,
  Zap,
} from "lucide-react";

export function HomeAgentPanel() {
  const {
    sendMessage,
    isLoading,
    resetActiveThread,
    subscribeTelemetry,
    subscribeIncident,
  } = useChatContext();
  const [inputText, setInputText] = useState("");
  const [activeTab, setActiveTab] = useState("Home");
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [historySearch, setHistorySearch] = useState("");
  const [isMinimized, setIsMinimized] = useState(false);

  const [liveTraffic, setLiveTraffic] = useState<any[]>([
    {
      id: "ip-1",
      ip: "192.168.1.104",
      flag: "🇺🇸",
      dotColor: "bg-emerald-500",
      description: "SMB Traffic - Nominal Internal Flow",
      time: "Just now",
    },
    {
      id: "ip-2",
      ip: "185.220.101.5",
      flag: "🇩🇪",
      dotColor: "bg-rose-500 animate-pulse",
      description: "SYN Port Sweep Reconnaissance Intercepted",
      time: "2m ago",
    },
    {
      id: "ip-3",
      ip: "45.33.32.156",
      flag: "🇯🇵",
      dotColor: "bg-emerald-500",
      description: "GET /api/v1/telemetry/ingest - 200 OK",
      time: "5m ago",
    },
  ]);

  // Subscribe to centralized WebSocket events from ChatProvider
  useEffect(() => {
    const unsubTelemetry = subscribeTelemetry((tick: any) => {
      const flagMap: Record<string, string> = {
        US: "🇺🇸", DE: "🇩🇪", JP: "🇯🇵", IN: "🇮🇳", GB: "🇬🇧",
        CA: "🇨🇦", FR: "🇫🇷", BR: "🇧🇷", AU: "🇦🇺", SG: "🇸🇬",
      };
      const flag = flagMap[tick.country] || "🌐";
      const newItem = {
        id: `tr-${Date.now()}-${Math.random()}`,
        ip: tick.src_ip,
        flag,
        dotColor: tick.is_anomaly ? "bg-rose-500 animate-pulse" : "bg-emerald-500",
        description: `${tick.protocol || "TCP"} Flow -> ${tick.domain || "Internal Gateway"} [BDI: ${tick.bdi_score}]`,
        time: "Just now",
      };
      setLiveTraffic((prev) => [newItem, ...prev.slice(0, 19)]);
    });

    const unsubIncident = subscribeIncident((inc: any) => {
      const newItem = {
        id: `tr-inc-${inc.incident_id}`,
        ip: inc.attacker_ip,
        flag: "🚨",
        dotColor: "bg-rose-500 animate-pulse",
        description: `CRITICAL ATTACK DETECTED: BDI ${inc.bdi_score} -> Target: ${inc.target_ip}`,
        time: "Just now",
      };
      setLiveTraffic((prev) => [newItem, ...prev.slice(0, 19)]);
    });

    return () => { unsubTelemetry(); unsubIncident(); };
  }, [subscribeTelemetry, subscribeIncident]);

  const tabs = ["Home", "Tasks"];

  const handleStart = () => {
    sendMessage({ text: "attack" });
  };


  // Connect listener so clicking attack triggers on the canvas feeds directly into chat
  useEffect(() => {
    const handleProceed = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (detail?.text) {
        setIsMinimized(false);
        sendMessage({ text: detail.text });
      }
    };
    window.addEventListener("aegis:proceed-tasks", handleProceed);
    return () => window.removeEventListener("aegis:proceed-tasks", handleProceed);
  }, [sendMessage]);

  const handleSend = () => {
    if (!inputText.trim() || isLoading) return;
    sendMessage({ text: inputText.trim() });
    setInputText("");
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Minimized floating trigger pill
  if (isMinimized) {
    return (
      <div className="flex items-end justify-end h-full p-3 pointer-events-auto">
        <button
          onClick={() => setIsMinimized(false)}
          className="flex items-center gap-3 px-4 py-2.5 rounded-full bg-[#0B0B0D]/95 hover:bg-[#1C1C22] border border-white/20 hover:border-white/40 shadow-2xl text-white text-xs font-medium backdrop-blur-xl transition-all duration-200 hover:scale-105 group"
        >
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
          <Bot className="w-4 h-4 text-cyan-400" />
          <span className="font-mono">AEGIS SOC Agent</span>
        </button>
      </div>
    );
  }

  return (
    <div className="w-[380px] shrink-0 h-full flex flex-col rounded-none overflow-hidden font-sans bg-[#0B0B0D]/95 backdrop-blur-xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.8),_0_0_20px_rgba(255,255,255,0.02)]">
      {/* Tab Header Bar — deep obsidian shade */}
      <div className="bg-[#0B0B0D] px-4 pt-3.5 pb-1 shrink-0">
        <div className="flex items-center justify-between text-[13px]">
          <div className="flex items-center gap-1.5">
            {tabs.map((tab) => (
              <button
                key={tab}
                onClick={() => {
                  setActiveTab(tab);
                  setIsHistoryOpen(false);
                }}
                className={`px-3.5 py-1.5 rounded-md font-medium transition-all duration-150 ${
                  activeTab === tab && !isHistoryOpen
                    ? "bg-[#1C1C22] text-white border border-white/15 shadow-sm"
                    : "text-neutral-400 hover:text-white hover:bg-white/[0.04]"
                }`}
              >
                <span>{tab}</span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            {/* Recent History Free-floating Icon Button */}
            <div className="relative group">
              <button
                onClick={() => setIsHistoryOpen(!isHistoryOpen)}
                className="p-2 rounded-md text-neutral-400 hover:text-white hover:bg-white/[0.06] transition-all flex items-center justify-center"
              >
                <History className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 top-full mt-1.5 hidden group-hover:block z-50 pointer-events-none">
                <div className="bg-[#1C1C24] text-white text-[11px] font-medium px-2.5 py-1 rounded shadow-xl border border-white/10 whitespace-nowrap">
                  Recent history
                </div>
              </div>
            </div>

            {/* New Session Free-floating Icon Button */}
            <div className="relative group">
              <button
                onClick={() => {
                  resetActiveThread();
                  setIsHistoryOpen(false);
                  setActiveTab("Home");
                }}
                className="p-2 rounded-md text-neutral-400 hover:text-white hover:bg-white/[0.06] transition-all flex items-center justify-center"
              >
                <Plus className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 top-full mt-1.5 hidden group-hover:block z-50 pointer-events-none">
                <div className="bg-[#1C1C24] text-white text-[11px] font-medium px-2.5 py-1 rounded shadow-xl border border-white/10 whitespace-nowrap">
                  New session
                </div>
              </div>
            </div>

            {/* Minimize Panel Button */}
            <div className="relative group">
              <button
                onClick={() => setIsMinimized(true)}
                className="p-2 rounded-md text-neutral-400 hover:text-white hover:bg-white/[0.06] transition-all flex items-center justify-center"
              >
                <Minus className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 top-full mt-1.5 hidden group-hover:block z-50 pointer-events-none">
                <div className="bg-[#1C1C24] text-white text-[11px] font-medium px-2.5 py-1 rounded shadow-xl border border-white/10 whitespace-nowrap">
                  Minimize panel
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Inner Content Panel */}
      <div className="flex-1 flex flex-col bg-[#0B0B0D]/95 backdrop-blur-lg rounded-t-lg border-t border-x border-white/20 mt-3 overflow-hidden shadow-[0_-6px_24px_rgba(0,0,0,0.6)]">
        {isHistoryOpen ? (
          /* Recent History Panel Overlay View */
          <div className="flex-1 flex flex-col p-5 overflow-y-auto">
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-white/10">
              <h3 className="text-[14px] font-medium text-white flex items-center gap-2">
                <History className="w-4 h-4 text-neutral-400" />
                Recent Conversations
              </h3>
              <button
                onClick={() => setIsHistoryOpen(false)}
                className="text-neutral-400 hover:text-white text-xs px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors"
              >
                Back to Feed
              </button>
            </div>

            <div className="relative mb-3">
              <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-neutral-500" />
              <input
                type="text"
                placeholder="Search history..."
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                className="w-full bg-[#121216] border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-neutral-500 focus:outline-none focus:border-white/30"
              />
            </div>

            <div className="flex flex-col gap-2 mt-2">
              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5 hover:border-white/10 transition-colors cursor-pointer group">
                <div className="flex items-center justify-between text-[11px] text-neutral-500 mb-1">
                  <span>Today, 10:45 AM</span>
                  <Trash2 className="w-3 h-3 opacity-0 group-hover:opacity-100 hover:text-red-400 transition-opacity" />
                </div>
                <p className="text-xs text-neutral-300 group-hover:text-white transition-colors truncate">
                  Triage anomalous SMB lateral flow to finance subnet
                </p>
              </div>

              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5 hover:border-white/10 transition-colors cursor-pointer group">
                <div className="flex items-center justify-between text-[11px] text-neutral-500 mb-1">
                  <span>Yesterday, 04:12 PM</span>
                  <Trash2 className="w-3 h-3 opacity-0 group-hover:opacity-100 hover:text-red-400 transition-opacity" />
                </div>
                <p className="text-xs text-neutral-300 group-hover:text-white transition-colors truncate">
                  Simulate high-velocity port sweep reconnaissance
                </p>
              </div>
            </div>
          </div>
        ) : activeTab === "Tasks" ? (
          /* Tasks View — Minimal Web Server Incoming Traffic & IP Feed */
          <div className="flex-1 min-h-0 flex flex-col p-4 overflow-y-auto custom-scrollbar font-mono text-white gap-3">
            <div className="flex items-center justify-between pb-2 border-b border-white/10 shrink-0">
              <span className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">
                Web Server Traffic
              </span>
              <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/20">
                LIVE TELEMETRY
              </span>
            </div>

            {/* Quick Simulation Trigger Actions */}
            <div className="flex items-center gap-2 font-mono">
              <button
                onClick={() => sendMessage({ text: "attack" })}
                className="flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-[11px] font-bold transition-all"
              >
                <Zap className="w-3 h-3" />
                <span>Inject Attack</span>
              </button>
              <button
                onClick={() => sendMessage({ text: "normal" })}
                className="flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-[11px] font-bold transition-all"
              >
                <span>🟢 Benign Burst</span>
              </button>
            </div>

            <div className="flex flex-col gap-2">
              {liveTraffic.map((item) => (
                <div
                  key={item.id}
                  onClick={() => sendMessage({ text: `Triage incoming traffic from IP ${item.ip}: ${item.description}` })}
                  className="p-2.5 bg-white/[0.02] border border-white/5 hover:border-white/20 hover:bg-white/[0.05] transition-all cursor-pointer group flex flex-col gap-1 select-none"
                >
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      {/* Green / Status Dot */}
                      <div className={`w-2 h-2 rounded-full ${item.dotColor}`} />
                      {/* Country Flag */}
                      <span className="text-sm leading-none">{item.flag}</span>
                      {/* Plain IP */}
                      <span className="font-mono text-neutral-200 group-hover:text-white font-medium">
                        {item.ip}
                      </span>
                    </div>

                    <span className="text-[10px] text-neutral-500 font-mono">
                      {item.time}
                    </span>
                  </div>

                  <p className="text-xs font-sans text-neutral-400 group-hover:text-neutral-300 transition-colors pl-4 truncate">
                    {item.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

        ) : (
          /* Active Chat Feed & Pinned Start Button */
          <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
            <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
              <AgentFeed />
            </div>

            {/* Bottom Right Pinned Start Button */}
            <div className="p-3 bg-[#0B0B0D] border-t border-white/10 flex items-center justify-end shrink-0 relative z-20">
              <button
                onClick={handleStart}
                disabled={isLoading}
                className="flex items-center gap-2 px-5 py-2 bg-white text-black hover:bg-neutral-200 text-xs font-bold font-mono transition-all duration-200 shadow-[0_0_15px_rgba(255,255,255,0.2)] active:scale-95 disabled:opacity-50 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-black text-black" />
                <span>Start</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
