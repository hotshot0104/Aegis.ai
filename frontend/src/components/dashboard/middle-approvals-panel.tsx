"use client";

import React, { useState, useEffect } from "react";
import { useChatContext } from "@/components/agent-feed/chat-provider";
import { aegisApi, type IncidentCard } from "@/lib/api-client";

interface ApprovalItem {
  id: string;
  ip: string;
  domain: string;
  actionTitle: string;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM";
  flag: string;
  reason: string;
  remediationCommands: string[];
  telemetrySource: string;
  timeAgo: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
}

const initialApprovals: ApprovalItem[] = [
  {
    id: "app-1",
    ip: "185.220.101.5",
    domain: "exit-node-05.tor.org",
    actionTitle: "Isolate Endpoint & Block SMB Traffic",
    riskLevel: "CRITICAL",
    flag: "🇩🇪",
    reason: "Detected high-velocity port sweep (1,240 SYN/s) followed by unauthorized SMB NTLM v2 hash relay targeting Finance Subnet (192.168.1.104). Risk Score: 0.96.",
    remediationCommands: [
      "iptables -A INPUT -s 185.220.101.5 -j DROP",
      "pkill -f smbd_relay && systemctl restart smbd",
    ],
    telemetrySource: "US-EAST-TOR-GATEWAY",
    timeAgo: "2m ago",
    status: "PENDING",
  },
  {
    id: "app-2",
    ip: "198.51.100.42",
    domain: "telemetry.aws-east.com",
    actionTitle: "Revoke Privileged IAM Access Token",
    riskLevel: "HIGH",
    flag: "🇨🇦",
    reason: "Anomaly detected in AWS STS AssumeRole token generation outside trusted CIDR blocks. Possible credential theft attempt.",
    remediationCommands: [
      "aws iam revoke-security-credentials --user-name soc-deploy-bot",
      "aws s3api put-bucket-policy --bucket aegis-vault --policy file://containment.json",
    ],
    telemetrySource: "AWS-CLOUD-TRAIL-INGRESS",
    timeAgo: "15m ago",
    status: "PENDING",
  },
  {
    id: "app-3",
    ip: "103.21.244.12",
    domain: "db-cluster-prod.internal",
    actionTitle: "Terminate Suspicious SQL Query",
    riskLevel: "MEDIUM",
    flag: "🇮🇳",
    reason: "Union-based SQL injection attempt intercepted on GET /api/v1/users endpoint. Sanitization filter triggered.",
    remediationCommands: [
      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%UNION SELECT%';",
    ],
    telemetrySource: "K8S-INGRESS-WAF",
    timeAgo: "32m ago",
    status: "PENDING",
  },
];

function mapIncidentToApproval(inc: IncidentCard): ApprovalItem {
  const isContained = inc.status === "CONTAINED";
  const isDismissed = inc.status === "DISMISSED";
  const statusStr = isContained ? "APPROVED" : isDismissed ? "REJECTED" : "PENDING";
  const riskStr = inc.bdi_score >= 0.9 ? "CRITICAL" : inc.bdi_score >= 0.7 ? "HIGH" : "MEDIUM";

  const iptables = inc.containment?.iptables_rule || `iptables -A INPUT -s ${inc.attacker_ip} -j DROP`;
  const powershell = inc.containment?.powershell_command || `Block-NetAdapter -IPAddress ${inc.attacker_ip}`;

  return {
    id: inc.incident_id,
    ip: inc.attacker_ip,
    domain: inc.asset?.hostname || inc.mitre_threat?.technique_name || "target-node",
    actionTitle: `Isolate Attacker & Enforce Firewall Lockdown (${inc.protocol || "TCP"})`,
    riskLevel: riskStr,
    flag: "🚨",
    reason: inc.agent_reasoning_summary || `High-risk anomaly (BDI ${inc.bdi_score}) detected targeting ${inc.target_ip}.`,
    remediationCommands: [iptables, powershell],
    telemetrySource: "AEGIS-MULTI-AGENT-DAG",
    timeAgo: "Just now",
    status: statusStr,
  };
}

export function MiddleApprovalsPanel() {
  const { sendMessage, subscribeIncident, subscribeContainment } = useChatContext();
  const [approvals, setApprovals] = useState<ApprovalItem[]>(initialApprovals);
  const [expandedId, setExpandedId] = useState<string | null>("app-1");
  const [searchQuery, setSearchQuery] = useState("");

  // Load active incidents from backend on mount
  useEffect(() => {
    const loadIncidents = async () => {
      try {
        const incidents = await aegisApi.getIncidents();
        if (incidents && incidents.length > 0) {
          const mapped = incidents.map(mapIncidentToApproval);
          setApprovals((prev) => {
            const existingIds = new Set(prev.map((a) => a.id));
            const fresh = mapped.filter((m) => !existingIds.has(m.id));
            return [...fresh, ...prev];
          });
        }
      } catch {
        // Handled
      }
    };
    loadIncidents();
  }, []);

  // Subscribe to centralized WebSocket events from ChatProvider
  useEffect(() => {
    const unsubIncident = subscribeIncident((inc: IncidentCard) => {
      const item = mapIncidentToApproval(inc);
      setApprovals((prev) => [item, ...prev.filter((a) => a.id !== item.id)]);
      setExpandedId(item.id);
    });

    const unsubContainment = subscribeContainment((c: any) => {
      setApprovals((prev) =>
        prev.map((a) => (a.id === c.incident_id ? { ...a, status: "APPROVED" } : a))
      );
    });

    return () => { unsubIncident(); unsubContainment(); };
  }, [subscribeIncident, subscribeContainment]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const handleApprove = async (item: ApprovalItem, e: React.MouseEvent) => {
    e.stopPropagation();
    setApprovals((prev) =>
      prev.map((a) => (a.id === item.id ? { ...a, status: "APPROVED" } : a))
    );

    // Only call backend for real incidents (not demo items starting with "app-")
    const isDemoItem = item.id.startsWith("app-");
    if (!isDemoItem) {
      try {
        await aegisApi.executeContainment({
          incident_id: item.id,
          rule_type: "iptables",
          officer_token: "SOC-OFFICER-AUTH-TOKEN-DEMO",
          approval_action: "APPROVE",
        });
      } catch {
        // Handled — containment may fail if incident was already contained
      }
    }

    sendMessage({
      text: `Approved SOC Action: ${item.actionTitle} for IP ${item.ip}. Executing containment: ${item.remediationCommands.join(" ; ")}`,
    });
  };

  const handleReject = async (item: ApprovalItem, e: React.MouseEvent) => {
    e.stopPropagation();
    setApprovals((prev) =>
      prev.map((a) => (a.id === item.id ? { ...a, status: "REJECTED" } : a))
    );

    const isDemoItem = item.id.startsWith("app-");
    if (!isDemoItem) {
      try {
        await aegisApi.executeContainment({
          incident_id: item.id,
          approval_action: "REJECT",
        });
      } catch {
        // Handled
      }
    }
  };

  const handleExecuteInTerminal = (item: ApprovalItem, e: React.MouseEvent) => {
    e.stopPropagation();
    sendMessage({
      text: `approve ${item.id}`,
    });
  };


  const filteredApprovals = approvals.filter(
    (a) =>
      a.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.actionTitle.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const pendingCount = approvals.filter((a) => a.status === "PENDING").length;

  return (
    <div className="w-full h-full flex flex-col bg-[#09090C] rounded-none overflow-hidden font-mono text-white select-none">
      {/* Clean Unboxed Header Bar */}
      <div className="h-10 border-b border-white/10 px-4 flex items-center justify-between shrink-0 bg-[#09090C]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-neutral-200 uppercase tracking-wider font-mono">
            Action Approvals
          </span>
          <span className="text-[10px] text-amber-400 font-mono">
            ({pendingCount} REQUIRED)
          </span>
        </div>

        {/* Minimal Search Bar */}
        <div className="flex items-center gap-1 bg-transparent px-2 py-0.5 text-xs text-neutral-400 font-mono">
          <span className="text-neutral-500 select-none">/</span>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="search IP..."
            className="bg-transparent focus:outline-none placeholder-neutral-600 text-xs text-white w-28"
          />
        </div>
      </div>

      {/* Unboxed Terminal Approval Item List */}
      <div className="flex-1 overflow-y-auto custom-scrollbar p-3 flex flex-col gap-3">
        {filteredApprovals.map((item) => {
          const isExpanded = expandedId === item.id;
          const isPending = item.status === "PENDING";

          return (
            <div
              key={item.id}
              onClick={() => toggleExpand(item.id)}
              className="flex flex-col border-b border-white/5 pb-2.5 cursor-pointer group"
            >
              {/* Unboxed Single Line Summary */}
              <div className="flex items-center justify-between text-xs py-1 hover:text-white transition-colors gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  {/* Chevron Indicator */}
                  <span className="text-neutral-500 text-[10px] select-none shrink-0">
                    {isExpanded ? "▼" : "▶"}
                  </span>

                  {/* Flag & Plain IP Address */}
                  <span className="text-sm leading-none shrink-0">{item.flag}</span>
                  <span className="font-mono text-neutral-200 group-hover:text-white font-medium shrink-0">
                    {item.ip}
                  </span>

                  {/* Clean Professional Action Title */}
                  <span className="font-sans text-xs text-neutral-300 font-medium group-hover:text-white truncate">
                    — {item.actionTitle}
                  </span>
                </div>

                {/* Right Side Simple Text Action Buttons */}
                <div className="flex items-center gap-3 shrink-0 ml-2">
                  {isPending ? (
                    <>
                      <button
                        onClick={(e) => handleApprove(item, e)}
                        className="text-xs font-mono text-emerald-400 hover:text-emerald-300 font-semibold transition-colors"
                      >
                        Approve
                      </button>
                      <button
                        onClick={(e) => handleReject(item, e)}
                        className="text-xs font-mono text-rose-400 hover:text-rose-300 transition-colors"
                      >
                        Reject
                      </button>
                    </>
                  ) : (
                    <span
                      className={`text-[10px] font-mono font-bold ${
                        item.status === "APPROVED" ? "text-emerald-400" : "text-rose-400"
                      }`}
                    >
                      [{item.status}]
                    </span>
                  )}
                </div>
              </div>

              {/* Unboxed Expanded Paragraph View */}
              {isExpanded && (
                <div className="pl-5 pt-2 flex flex-col gap-2 text-xs text-neutral-300 font-mono">
                  {/* Domain & Source Line */}
                  <div className="text-[11px] text-neutral-400">
                    Domain: <span className="text-neutral-200">{item.domain}</span> | Source: <span className="text-neutral-300">{item.telemetrySource}</span> ({item.timeAgo})
                  </div>

                  {/* Flagged Reason Paragraph */}
                  <div className="flex flex-col gap-0.5">
                    <span className="text-[11px] text-amber-400 font-bold">
                      Flagged Reason:
                    </span>
                    <p className="text-neutral-300 font-sans text-xs leading-relaxed pl-2 border-l border-amber-500/40">
                      {item.reason}
                    </p>
                  </div>

                  {/* Proposed Remediation Commands */}
                  <div className="flex flex-col gap-1 mt-1">
                    <span className="text-[11px] text-cyan-400 font-bold">
                      Proposed Remediation Commands:
                    </span>
                    <div className="pl-2 flex flex-col gap-0.5 text-[11px] text-cyan-200">
                      {item.remediationCommands.map((cmd, idx) => (
                        <div key={idx} className="flex items-center gap-1.5">
                          <span className="text-neutral-500 select-none">$</span>
                          <span>{cmd}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Execute Button Link */}
                  <div className="mt-1 pt-1">
                    <button
                      onClick={(e) => handleExecuteInTerminal(item, e)}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 transition-colors"
                    >
                      &gt; Execute in Okara Terminal
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
