# AEGIS-AI — Cyber Command Dashboard

High-performance real-time Security Operations Center (SOC) dashboard for **Project AEGIS-AI** (Autonomous Agentic SOC & Non-IoC Network Compromise Defense).

---

## Overview

AEGIS-AI provides an intuitive, high-contrast dark command center designed for cyber operators and SOC analysts to:
1. **Monitor Live Telemetry**: Visualize packet and statistical flow throughput streaming at $10\text{ flows/sec}$.
2. **Observe Real-Time Multi-Agent Reasoning**: Stream live Chain-of-Thought traces from the **Supervisor**, **Threat Hunter**, **Asset Investigator**, and **Rule Generator** agents.
3. **Inspect Subnet Topology & Blast Radius**: Interactive visual node graphs identifying rogue attacker IPs and targeted enterprise Crown Jewels.
4. **Authorize Human-in-the-Loop Containment**: Review pre-compiled platform-specific firewall drop scripts (`iptables`, `Cisco IOS ACL`, `Windows PowerShell`) and authorize isolation with cryptographic HMAC-SHA256 audit signing (**Rule 3**).
5. **Generate CISO Daily Briefs**: Export C-suite ready executive incident summaries.

---

## Tech Stack

- **Framework**: Next.js 15 (App Router) + React 19
- **Styling**: Tailwind CSS 4 + Shadcn UI component primitives
- **Real-Time Streaming**: Native WebSockets (`/ws/telemetry` & `/ws/agent-thoughts`)
- **Theme**: Cyberpunk Military SOC Dark Glassmorphism (`#070a13` Obsidian Void)

---

## Getting Started

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env.local

# 3. Start development server
npm run dev
```

Open [http://localhost:3001](http://localhost:3001) to view the Cyber Command Center.
