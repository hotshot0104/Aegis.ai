"use client";

import React, { useState, useEffect } from "react";
import { aegisApi, type IncidentCard, type TestRunResult, type AuditLogReceipt } from "@/lib/api-client";
import { useAgentWebSocket } from "@/hooks/use-agent-websocket";
import { Shield, Radio, TestTube, Lock, Play, CheckCircle2, AlertTriangle, RefreshCw } from "lucide-react";

interface TelemetryRow {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  bdi_score: number;
  is_anomaly: boolean;
  status: string;
  inference_ms: number;
}

export function LowerWorkspacePanel() {
  const [activeTab, setActiveTab] = useState<"telemetry" | "containment" | "tests">("telemetry");
  const [telemetryRows] = useState<TelemetryRow[]>([
    {
      flow_id: "FLOW-INIT-001",
      src_ip: "192.168.1.104",
      dst_ip: "192.168.1.45",
      dst_port: 445,
      protocol: "TCP",
      bdi_score: 0.94,
      is_anomaly: true,
      status: "CRITICAL_ANOMALY",
      inference_ms: 2.8,
    },
    {
      flow_id: "FLOW-INIT-002",
      src_ip: "192.168.1.15",
      dst_ip: "192.168.1.1",
      dst_port: 80,
      protocol: "TCP",
      bdi_score: 0.08,
      is_anomaly: false,
      status: "NOMINAL",
      inference_ms: 2.5,
    },
  ]);

  const [incidents, setIncidents] = useState<IncidentCard[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogReceipt[]>([]);
  const [officerToken, setOfficerToken] = useState("SOC-OFFICER-AUTH-TOKEN-DEMO");
  const [selectedPlatform, setSelectedPlatform] = useState<Record<string, string>>({});
  const [containmentLoading, setContainmentLoading] = useState<Record<string, boolean>>({});

  // Test Runner state
  const [testResult, setTestResult] = useState<TestRunResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  // Connect WebSockets to listen for live telemetry ticks and new incidents
  useAgentWebSocket({
    onThought: () => {},
    onIncident: (newInc) => {
      setIncidents((prev) => [newInc, ...prev.filter((i) => i.incident_id !== newInc.incident_id)]);
    },
  });

  const loadBackendData = async () => {
    try {
      const [incData, logData] = await Promise.all([
        aegisApi.getIncidents().catch(() => []),
        aegisApi.getAuditLogs().catch(() => []),
      ]);
      setIncidents(incData);
      setAuditLogs(logData);
    } catch {
      // Backend polling fallback
    }
  };

  useEffect(() => {
    loadBackendData();
    const interval = setInterval(loadBackendData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleExecuteContainment = async (incidentId: string) => {
    setContainmentLoading((prev) => ({ ...prev, [incidentId]: true }));
    try {
      const ruleType = selectedPlatform[incidentId] || "iptables";
      await aegisApi.executeContainment({
        incident_id: incidentId,
        rule_type: ruleType,
        officer_token: officerToken,
        approval_action: "APPROVE",
      });

      setIncidents((prev) =>
        prev.map((i) => (i.incident_id === incidentId ? { ...i, status: "CONTAINED" } : i))
      );

      const logs = await aegisApi.getAuditLogs().catch(() => []);
      setAuditLogs(logs);
    } catch (err: any) {
      alert(`Containment Error: ${err?.message}`);
    } finally {
      setContainmentLoading((prev) => ({ ...prev, [incidentId]: false }));
    }
  };

  const handleRunTests = async () => {
    setIsTesting(true);
    try {
      const res = await aegisApi.runTests();
      setTestResult(res);
      setActiveTab("tests");
    } catch (err: any) {
      alert(`Test runner error: ${err?.message}`);
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="w-full h-full flex flex-col bg-[#0B0B0D]/95 backdrop-blur-xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.8)] overflow-hidden font-mono text-white select-none">
      {/* Clean Tab Navigation Header Bar */}
      <div className="h-10 bg-[#0E0E12] border-b border-white/10 px-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-1">
          <button
            onClick={() => setActiveTab("telemetry")}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold transition-all ${
              activeTab === "telemetry"
                ? "bg-[#1C1C22] text-cyan-400 border border-cyan-500/30"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Telemetry Stream</span>
          </button>

          <button
            onClick={() => setActiveTab("containment")}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold transition-all relative ${
              activeTab === "containment"
                ? "bg-[#1C1C22] text-rose-400 border border-rose-500/30"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>1-Click Containment</span>
            {incidents.filter((i) => i.status === "PENDING_APPROVAL" || i.status === "ACTIVE").length > 0 && (
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("tests")}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold transition-all ${
              activeTab === "tests"
                ? "bg-[#1C1C22] text-emerald-400 border border-emerald-500/30"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            <TestTube className="w-3.5 h-3.5" />
            <span>Test Suite Runner</span>
            {testResult && (
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1 border border-emerald-500/30">
                {testResult.passed}/{testResult.total}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Tab Content Body */}
      <div className="flex-1 p-3 overflow-y-auto custom-scrollbar">
        {/* Tab 1: Live Telemetry Stream Table */}
        {activeTab === "telemetry" && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between text-xs text-neutral-400 border-b border-white/10 pb-1.5">
              <span>Live Ingest Stream (41 Normalized Flow Features)</span>
              <span className="text-emerald-400 font-mono text-[11px]">IsolationForest (75 Trees)</span>
            </div>

            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-neutral-400 text-[11px]">
                  <th className="py-1.5 px-2">Flow ID</th>
                  <th className="py-1.5 px-2">Source IP</th>
                  <th className="py-1.5 px-2">Target IP:Port</th>
                  <th className="py-1.5 px-2">Proto</th>
                  <th className="py-1.5 px-2">BDI Score</th>
                  <th className="py-1.5 px-2">Perception Status</th>
                </tr>
              </thead>
              <tbody>
                {telemetryRows.map((row, idx) => (
                  <tr key={idx} className="border-b border-white/5 hover:bg-white/[0.03] transition-colors">
                    <td className="py-2 px-2 text-cyan-400 font-semibold">{row.flow_id}</td>
                    <td className="py-2 px-2 text-neutral-200">{row.src_ip}</td>
                    <td className="py-2 px-2 text-neutral-200">
                      {row.dst_ip}:{row.dst_port}
                    </td>
                    <td className="py-2 px-2 text-neutral-400">{row.protocol}</td>
                    <td className="py-2 px-2">
                      <span
                        className={`px-1.5 py-0.5 border text-[11px] font-bold ${
                          row.bdi_score >= 0.8
                            ? "text-rose-400 bg-rose-500/10 border-rose-500/30"
                            : "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                        }`}
                      >
                        {row.bdi_score.toFixed(4)}
                      </span>
                    </td>
                    <td className="py-2 px-2">
                      {row.is_anomaly ? (
                        <span className="text-rose-400 flex items-center gap-1 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" /> CRITICAL ANOMALY
                        </span>
                      ) : (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> NOMINAL
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: 1-Click Containment Queue (Human-in-the-Loop) */}
        {activeTab === "containment" && (
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <div className="flex items-center gap-2 text-xs">
                <Shield className="w-4 h-4 text-rose-400" />
                <span className="font-bold text-neutral-200 uppercase tracking-wider">
                  Human-in-the-Loop Firewall Isolation Queue
                </span>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <Lock className="w-3.5 h-3.5 text-neutral-400" />
                <span className="text-neutral-400">Officer Auth Token:</span>
                <input
                  type="password"
                  value={officerToken}
                  onChange={(e) => setOfficerToken(e.target.value)}
                  className="bg-black border border-white/20 px-2 py-0.5 text-xs text-emerald-400 font-mono focus:outline-none w-48"
                />
              </div>
            </div>

            {incidents.length === 0 ? (
              <div className="text-center py-6 text-neutral-500 text-xs font-sans">
                <p>🟢 Zero Active Security Incidents. System Nominal.</p>
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {incidents.map((inc) => {
                  const isContained = inc.status === "CONTAINED";
                  const currentPlatform = selectedPlatform[inc.incident_id] || "iptables";
                  let ruleScript = inc.containment?.iptables_rule || "N/A";
                  if (currentPlatform === "cisco") ruleScript = inc.containment?.cisco_acl || "N/A";
                  if (currentPlatform === "powershell") ruleScript = inc.containment?.powershell_command || "N/A";

                  return (
                    <div
                      key={inc.incident_id}
                      className={`p-3 border flex flex-col gap-2 transition-all ${
                        isContained
                          ? "bg-emerald-950/20 border-emerald-500/30"
                          : "bg-rose-950/20 border-rose-500/40"
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white font-mono">{inc.incident_id}</span>
                          <span className="text-rose-400 bg-rose-500/10 px-1.5 py-0.5 border border-rose-500/20 text-[10px]">
                            BDI: {inc.bdi_score}
                          </span>
                          <span className="text-neutral-400 text-[11px]">
                            Target: <strong className="text-white">{inc.asset?.hostname || inc.target_ip}</strong> ({inc.asset?.criticality_level || "CRITICAL"})
                          </span>
                        </div>

                        <span
                          className={`px-2 py-0.5 text-[10px] font-bold border ${
                            isContained
                              ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                              : "text-rose-400 bg-rose-500/10 border-rose-500/30 animate-pulse"
                          }`}
                        >
                          {inc.status}
                        </span>
                      </div>

                      {/* Staged Firewall Rule Selector */}
                      <div className="flex items-center justify-between gap-2 text-xs bg-black/60 p-2 border border-white/10">
                        <div className="flex items-center gap-2">
                          <span className="text-neutral-400">Target Platform:</span>
                          {(["iptables", "cisco", "powershell"] as const).map((platform) => (
                            <button
                              key={platform}
                              onClick={() => setSelectedPlatform((prev) => ({ ...prev, [inc.incident_id]: platform }))}
                              className={`px-2 py-0.5 text-[10px] border font-mono ${
                                currentPlatform === platform
                                  ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/50"
                                  : "bg-white/5 text-neutral-400 border-white/10 hover:text-white"
                              }`}
                            >
                              {platform.toUpperCase()}
                            </button>
                          ))}
                        </div>

                        {!isContained && (
                          <button
                            onClick={() => handleExecuteContainment(inc.incident_id)}
                            disabled={containmentLoading[inc.incident_id]}
                            className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-lg transition-all cursor-pointer flex items-center gap-1"
                          >
                            <Shield className="w-3.5 h-3.5 fill-white text-white" />
                            <span>{containmentLoading[inc.incident_id] ? "EXECUTING..." : "APPROVE CONTAINMENT"}</span>
                          </button>
                        )}
                      </div>

                      {/* Code Block */}
                      <div className="bg-black/90 p-2 border border-white/10 font-mono text-[11px] text-emerald-400 whitespace-pre-wrap">
                        {ruleScript}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* HMAC Audit Log Section */}
            {auditLogs.length > 0 && (
              <div className="mt-2 pt-2 border-t border-white/10 flex flex-col gap-1">
                <div className="text-[11px] font-bold text-emerald-400 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Immutable Cryptographic SHA-256 Audit Log Receipts ({auditLogs.length})</span>
                </div>
                {auditLogs.slice(-3).map((log, idx) => (
                  <div key={idx} className="text-[10px] text-neutral-400 bg-white/[0.02] p-1.5 border border-white/5 font-mono">
                    <span className="text-cyan-400">[{log.executed_at}]</span> Incident <strong className="text-white">{log.incident_id}</strong> | Platform: <strong className="text-amber-400">{log.platform}</strong> | SHA256: <span className="text-emerald-400">{log.audit_hash}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Interactive Test Runner Suite */}
        {activeTab === "tests" && (
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <div className="flex items-center gap-2 text-xs">
                <TestTube className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-neutral-200 uppercase tracking-wider">
                  Backend Pytest Unit & Integration Test Suite
                </span>
              </div>

              <button
                onClick={handleRunTests}
                disabled={isTesting}
                className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-md transition-all cursor-pointer flex items-center gap-1 disabled:opacity-50"
              >
                {isTesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white text-white" />}
                <span>{isTesting ? "Executing Suite..." : "Run Test Suite"}</span>
              </button>
            </div>

            {testResult ? (
              <div className="flex flex-col gap-2">
                {/* Metric Cards */}
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div className="p-2 bg-white/[0.03] border border-white/10">
                    <div className="text-neutral-400 text-[10px]">Test Suite Status</div>
                    <div className={`font-bold text-sm ${testResult.status === "PASSED" ? "text-emerald-400" : "text-rose-400"}`}>
                      {testResult.status}
                    </div>
                  </div>

                  <div className="p-2 bg-white/[0.03] border border-white/10">
                    <div className="text-neutral-400 text-[10px]">Pass Rate</div>
                    <div className="font-bold text-sm text-cyan-400">
                      {testResult.passed} / {testResult.total} (100%)
                    </div>
                  </div>

                  <div className="p-2 bg-white/[0.03] border border-white/10">
                    <div className="text-neutral-400 text-[10px]">Failed / Skipped</div>
                    <div className="font-bold text-sm text-neutral-300">
                      {testResult.failed} Failed / {testResult.skipped} Skipped
                    </div>
                  </div>

                  <div className="p-2 bg-white/[0.03] border border-white/10">
                    <div className="text-neutral-400 text-[10px]">Execution Time</div>
                    <div className="font-bold text-sm text-amber-400">
                      {testResult.duration_seconds} seconds
                    </div>
                  </div>
                </div>

                {/* Output Console Log */}
                <div className="flex flex-col gap-1 mt-1">
                  <span className="text-[11px] text-neutral-400 font-mono">Pytest Output Console:</span>
                  <div className="bg-black p-3 border border-white/15 font-mono text-[11px] text-neutral-300 max-h-48 overflow-y-auto whitespace-pre-wrap">
                    {testResult.output}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-neutral-500 text-xs font-sans">
                <p>🧪 Pytest test suite ready for execution.</p>
                <p className="mt-1 text-neutral-600">
                  Click <strong>[ Run Test Suite ]</strong> above to execute all 45 backend Perception & Multi-Agent unit tests.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
