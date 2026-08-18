"use client";

import React, { useState, useEffect, useMemo } from "react";
import { aegisApi, type FleetStats, type IncidentCard } from "@/lib/api-client";
import { useChatContext } from "@/components/agent-feed/chat-provider";

export function DashboardLeftPane() {
  const [stats, setStats] = useState<FleetStats | null>(null);
  const [incidents, setIncidents] = useState<IncidentCard[]>([]);
  const { sendMessage, subscribeTelemetry, subscribeIncident } = useChatContext();

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [s, inc] = await Promise.all([
          aegisApi.getFleetStats(),
          aegisApi.getIncidents(),
        ]);
        setStats(s);
        setIncidents(inc);
      } catch {
        // Handled
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, []);

  const [liveScore, setLiveScore] = useState<number | null>(null);
  const [liveStreamItems, setLiveStreamItems] = useState<any[]>([]);

  // Subscribe to centralized WebSocket events from ChatProvider
  useEffect(() => {
    const unsubTelemetry = subscribeTelemetry((tick: any) => {
      if (tick.bdi_score !== undefined) {
        setLiveScore(tick.bdi_score);
      }
      const flagMap: Record<string, string> = {
        US: "🇺🇸", DE: "🇩🇪", JP: "🇯🇵", IN: "🇮🇳", GB: "🇬🇧",
        CA: "🇨🇦", FR: "🇫🇷", BR: "🇧🇷", AU: "🇦🇺", SG: "🇸🇬",
        NL: "🇳🇱", SE: "🇸🇪", KR: "🇰🇷", IT: "🇮🇹", ES: "🇪🇸",
      };
      const flag = flagMap[tick.country] || "🌐";
      const newItem = {
        id: `ws-${Date.now()}-${Math.random()}`,
        ip: tick.src_ip,
        flag,
        dotColor: tick.is_anomaly ? "bg-rose-500 animate-pulse" : "bg-emerald-500",
        domain: tick.domain || "aegis-fleet-node.net",
        time: "Just now",
      };
      setLiveStreamItems((prev) => [newItem, ...prev.slice(0, 49)]);
    });

    const unsubIncident = subscribeIncident((inc: IncidentCard) => {
      if (inc.bdi_score) {
        setLiveScore(inc.bdi_score);
      }
      const newItem = {
        id: `inc-${inc.incident_id}`,
        ip: inc.attacker_ip,
        flag: "🚨",
        dotColor: "bg-rose-500 animate-pulse",
        domain: `CRITICAL ATTACKER [BDI: ${inc.bdi_score}]`,
        time: "Just now",
      };
      setLiveStreamItems((prev) => [newItem, ...prev.slice(0, 49)]);
    });

    return () => { unsubTelemetry(); unsubIncident(); };
  }, [subscribeTelemetry, subscribeIncident]);

  const activeIncidents = incidents.filter((i) => i.status === "PENDING_APPROVAL" || i.status === "ACTIVE");
  const bdiScore = liveScore ?? (
    activeIncidents.length > 0 
      ? Math.max(...activeIncidents.map((i) => i.bdi_score)) 
      : (stats?.avg_bdi_score ?? 0.08)
  );

  // Single Ring Geometry (ViewBox 160 x 160)
  const rRing = 56;
  const cRing = 2 * Math.PI * rRing;
  const ringOffset = cRing * (1 - Math.min(0.99, Math.max(0.01, bdiScore)));

  // Initial baseline IP entries
  const baselineFeed = useMemo(() => {
    const flags = ["🇺🇸", "🇩🇪", "🇯🇵", "🇮🇳", "🇬🇧", "🇨🇦", "🇫🇷", "🇧🇷", "🇦🇺", "🇸🇬", "🇳🇱", "🇸🇪", "🇰🇷", "🇮🇹", "🇪🇸"];
    const domains = [
      "api.aegis.cloud",
      "finance.subnet.internal",
      "auth-gateway.aegis.io",
      "exit-node-05.tor.org",
      "telemetry.aws-east.com",
      "webhook.github.com",
      "cdn-edge.cloudflare.com",
      "s3-vault.amazonaws.com",
      "statuspage.io",
      "db-cluster-prod.internal",
      "k8s-ingress.aegis.dev",
      "monitoring.datadog.com",
    ];

    const list = [];
    for (let i = 1; i <= 30; i++) {
      const flag = flags[i % flags.length];
      const octet1 = (10 + (i * 7) % 200);
      const octet2 = (i * 13) % 255;
      const octet3 = (i * 29) % 255;
      const octet4 = (i * 41) % 255;
      const ip = `${octet1}.${octet2}.${octet3}.${octet4}`;
      const domain = domains[i % domains.length];
      const isAnomalous = i % 8 === 0;
      const dotColor = isAnomalous ? "bg-rose-500 animate-pulse" : "bg-emerald-500";
      const time = `${(i % 50) + 1}s ago`;

      list.push({
        id: `ip-${i}`,
        ip,
        flag,
        dotColor,
        domain,
        time,
      });
    }
    return list;
  }, []);

  const combinedFeed = [...liveStreamItems, ...baselineFeed];
  const loopedFeed = [...combinedFeed, ...combinedFeed];


  return (
    <div className="w-full h-full flex flex-col gap-2 font-sans text-white select-none">
      {/* Inline styles for continuous smooth scrolling */}
      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes ipFlowAnimation {
          0% {
            transform: translateY(0);
          }
          100% {
            transform: translateY(-50%);
          }
        }
        .animate-ip-flow {
          animation: ipFlowAnimation 140s linear infinite;
        }
        .animate-ip-flow:hover {
          animation-play-state: paused;
        }
      ` }} />

      {/* Upper Card (30% Vertical Height) — Single BDI Green Ring Widget */}
      <div className="h-[30%] min-h-[175px] w-full rounded-none bg-black border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.9)] overflow-hidden p-2 flex items-center justify-center relative">
        <div className="w-40 h-40 relative flex items-center justify-center shrink-0">
          <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 160 160">
            {/* Dark Olive/Green Background Track */}
            <circle
              cx="80"
              cy="80"
              r={rRing}
              stroke="#143306"
              strokeWidth="14"
              fill="none"
            />

            {/* Neon Lime Active Progress Arc */}
            <circle
              cx="80"
              cy="80"
              r={rRing}
              stroke="#99FF00"
              strokeWidth="14"
              fill="none"
              strokeDasharray={cRing}
              strokeDashoffset={ringOffset}
              strokeLinecap="round"
              className="transition-all duration-700 ease-out"
            />
          </svg>

          {/* Center Text: Dynamic Score & BDI INDEX Label */}
          <div className="absolute inset-0 flex flex-col items-center justify-center font-mono pointer-events-none select-none">
            <span className="text-2xl font-bold tracking-tight text-white leading-none">
              {bdiScore.toFixed(2)}
            </span>
            <span className="text-[10px] font-bold tracking-[0.18em] text-[#FA114F] uppercase mt-1">
              BDI INDEX
            </span>
          </div>
        </div>
      </div>

      {/* Lower Card (70% Vertical Height) — Live Continuous Flowing IP Telemetry Feed */}
      <div className="h-[70%] w-full rounded-none bg-black border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.9)] overflow-hidden flex flex-col p-4 font-sans text-white select-none">
        {/* Header Bar */}
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/10 shrink-0 relative z-10 bg-black">
          <span className="text-sm font-semibold text-neutral-200 font-sans tracking-wide">
            IP Visits
          </span>
          <div className="flex items-center gap-1.5 text-xs text-neutral-400 font-sans">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Live Stream</span>
          </div>
        </div>

        {/* Continuous Flowing Unboxed IP Telemetry Lines */}
        <div className="flex-1 min-h-0 overflow-hidden relative">
          <div className="animate-ip-flow flex flex-col gap-2.5">
            {loopedFeed.map((item, idx) => (
              <div
                key={`${item.id}-${idx}`}
                onClick={() => sendMessage({ text: `Triage incoming traffic from IP ${item.ip} (${item.domain})` })}
                className="flex items-center justify-between text-xs py-0.5 hover:text-white transition-colors cursor-pointer group shrink-0"
              >
                <div className="flex items-center gap-2 min-w-0">
                  {/* Status Indicator Dot */}
                  <div className={`w-2 h-2 rounded-full shrink-0 ${item.dotColor}`} />
                  {/* Country Flag Emoji */}
                  <span className="text-sm leading-none shrink-0">{item.flag}</span>
                  {/* Plain IP Address — NO brackets, NO boxes */}
                  <span className="font-mono text-neutral-200 group-hover:text-white font-medium shrink-0">
                    {item.ip}
                  </span>
                  {/* Main Domain */}
                  <span className="font-mono text-[11px] text-neutral-400 group-hover:text-neutral-200 truncate">
                    — {item.domain}
                  </span>
                </div>

                {/* Timestamp */}
                <span className="text-[10px] text-neutral-500 font-mono shrink-0 ml-2">
                  {item.time}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
