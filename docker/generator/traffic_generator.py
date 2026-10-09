#!/usr/bin/env python3
"""
Live Multi-Subnet IP Telemetry Generator for Project RAKSHA-AI.
Simulates a live enterprise network by continuously sending flow vectors
with realistic internal, DMZ, and adversary IP addresses into the RAKSHA-AI
telemetry stream endpoint (/api/v1/telemetry/stream).

Strictly zero third-party dependencies (pure standard library: urllib, json, time).
"""

import os
import sys
import time
import json
import random
import uuid
import argparse
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOPOLOGY_FILE = os.path.join(SCRIPT_DIR, "scenario_ips.json")

# Default IPs if scenario_ips.json is not found
DEFAULT_ASSETS = {
    "192.168.1.10": {"hostname": "DC-AD-CORE-01", "role": "Domain Controller"},
    "192.168.1.50": {"hostname": "DB-PROD-FINANCE-01", "role": "Crown Jewel Finance DB"},
    "192.168.1.60": {"hostname": "FS-CORP-SHARE-01", "role": "File Server"},
    "192.168.1.101": {"hostname": "WS-ENG-ALICE", "role": "Engineering Workstation"},
    "192.168.1.102": {"hostname": "WS-FIN-BOB", "role": "Finance Workstation"},
    "172.16.10.20": {"hostname": "WEB-NGINX-DMZ", "role": "DMZ Web Server"},
    "172.16.10.25": {"hostname": "MAIL-POSTFIX-01", "role": "Mail Gateway"}
}

DEFAULT_ADVERSARIES = {
    "198.51.100.23": {"alias": "APT-RECON-BOT"},
    "185.220.101.5": {"alias": "C2-COBALT-STRIKE"},
    "45.33.32.156": {"alias": "EXFIL-DROP-SERVER"}
}


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


class TelemetryStreamGenerator:
    def __init__(self, backend_url: str, interval: float = 0.8, attack_interval: int = 15):
        self.backend_url = backend_url.rstrip("/")
        self.stream_endpoint = f"{self.backend_url}/api/v1/telemetry/stream"
        self.interval = interval
        self.attack_interval = attack_interval
        self.load_topology()
        self.tick_count = 0

    def load_topology(self):
        if os.path.exists(TOPOLOGY_FILE):
            with open(TOPOLOGY_FILE, "r") as f:
                data = json.load(f)
                self.assets = data.get("assets", DEFAULT_ASSETS)
                self.adversaries = data.get("adversaries", DEFAULT_ADVERSARIES)
        else:
            self.assets = DEFAULT_ASSETS
            self.adversaries = DEFAULT_ADVERSARIES

    def send_flow(self, flow_payload: dict) -> dict:
        data_bytes = json.dumps(flow_payload).encode("utf-8")
        req = urllib.request.Request(
            self.stream_endpoint,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                res_body = resp.read().decode("utf-8")
                return json.loads(res_body)
        except urllib.error.URLError as e:
            return {"error": str(e), "bdi_score": 0.0, "status": "BACKEND_UNREACHABLE"}

    def generate_normal_flow(self) -> dict:
        """Generates legitimate baseline enterprise traffic."""
        client_ips = ["192.168.1.101", "192.168.1.102", "192.168.1.103"]
        server_ips = ["172.16.10.20", "192.168.1.10", "192.168.1.60"]
        
        src = random.choice(client_ips)
        dst = random.choice(server_ips)
        
        if dst == "172.16.10.20":  # Web
            port = random.choice([80, 443])
            service = "http"
            protocol = "TCP"
            src_bytes = random.randint(180, 950)
            dst_bytes = random.randint(1200, 15000)
        elif dst == "192.168.1.10":  # AD / LDAP / DNS
            port = random.choice([88, 389, 53])
            service = "domain_u" if port == 53 else "ldap"
            protocol = "UDP" if port == 53 else "TCP"
            src_bytes = random.randint(60, 220)
            dst_bytes = random.randint(100, 850)
        else:  # File Share
            port = 445
            service = "smb"
            protocol = "TCP"
            src_bytes = random.randint(300, 2400)
            dst_bytes = random.randint(400, 8000)

        features = {
            "duration": round(random.uniform(0.01, 1.5), 3),
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": random.randint(1, 6),
            "srv_count": random.randint(1, 4),
            "logged_in": 1,
            "num_failed_logins": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": random.randint(5, 50),
            "dst_host_srv_count": random.randint(5, 40),
            "service": service,
            "flag": "SF"
        }

        return {
            "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": port,
            "protocol": protocol,
            "features": features
        }

    def generate_attack_flow(self, attack_type: str = "lateral_movement") -> dict:
        """Generates realistic non-IoC zero-day compromise telemetry."""
        if attack_type == "syn_scan":
            # MITRE T1046: Network Service Scanning
            src = "198.51.100.23"  # APT-RECON-BOT
            dst = "172.16.10.20"   # WEB-NGINX-DMZ
            port = random.choice([21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080])
            features = {
                "duration": 0.0,
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": random.randint(350, 500),
                "srv_count": random.randint(350, 500),
                "logged_in": 0,
                "num_failed_logins": 0,
                "serror_rate": 1.0,
                "srv_serror_rate": 1.0,
                "dst_host_serror_rate": 1.0,
                "same_srv_rate": 0.05,
                "diff_srv_rate": 0.95,
                "service": "private",
                "flag": "S0"
            }
            protocol = "TCP"
        elif attack_type == "brute_force":
            # MITRE T1110: Credential Stuffing on Mail Gateway
            src = "198.51.100.23"
            dst = "172.16.10.25"  # MAIL-POSTFIX-01
            port = 110  # POP3
            features = {
                "duration": round(random.uniform(2.5, 6.0), 2),
                "src_bytes": random.randint(60, 150),
                "dst_bytes": random.randint(80, 200),
                "count": random.randint(120, 200),
                "srv_count": random.randint(120, 200),
                "logged_in": 0,
                "num_failed_logins": 1,
                "dst_host_count": 255,
                "dst_host_srv_count": random.randint(180, 240),
                "service": "pop_3",
                "flag": "SF"
            }
            protocol = "TCP"
        elif attack_type == "c2_beacon":
            # MITRE T1071.001: Web Protocol C2 Beaconing Channel
            src = "192.168.1.102"   # Compromised Finance WS
            dst = "185.220.101.5"   # C2-COBALT-STRIKE
            port = 443
            features = {
                "duration": 4.5,
                "src_bytes": 256,
                "dst_bytes": 256,  # Uniform identical payload sizes
                "count": 48,
                "srv_count": 48,
                "logged_in": 1,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 0.95,
                "service": "http",
                "flag": "SF"
            }
            protocol = "TCP"
        else:  # lateral_movement (Default Crown Jewel exploit)
            # MITRE T1021.002: SMB Lateral Movement into Finance Database
            src = "172.16.10.20"   # Compromised DMZ node
            dst = "192.168.1.50"   # Crown Jewel DB-PROD-FINANCE-01
            port = 445
            features = {
                "duration": round(random.uniform(0.8, 2.5), 2),
                "src_bytes": random.randint(85000, 140000),
                "dst_bytes": random.randint(45000, 80000),
                "count": random.randint(35, 60),
                "srv_count": random.randint(35, 60),
                "logged_in": 1,
                "root_shell": 1,
                "su_attempted": 1,
                "num_root": random.randint(3, 10),
                "num_file_creations": random.randint(2, 5),
                "dst_host_count": random.randint(80, 150),
                "dst_host_srv_count": random.randint(80, 150),
                "service": "smb",
                "flag": "SF"
            }
            protocol = "TCP"

        return {
            "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": port,
            "protocol": protocol,
            "features": features
        }

    def print_banner(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}║   PROJECT RAKSHA-AI: LIVE MULTI-SUBNET IP TELEMETRY SIMULATOR PROBE     ║{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        print(f"[*] Target Backend Endpoint: {Colors.BLUE}{self.stream_endpoint}{Colors.RESET}")
        print(f"[*] Flow Stream Interval:    {self.interval}s per tick")
        print(f"[*] Attack Wave Interval:    Every {self.attack_interval} ticks (~{self.interval * self.attack_interval:.1f}s)")
        print(f"[*] Subnet Catalog:          Internal (192.168.1.0/24) | DMZ (172.16.10.0/24) | WAN Adversaries")
        print(f"{Colors.YELLOW}[!] Press Ctrl+C at any time to pause or stop simulation.{Colors.RESET}\n")

    def run(self):
        self.print_banner()
        attack_types = ["lateral_movement", "syn_scan", "brute_force", "c2_beacon"]
        attack_idx = 0

        while True:
            self.tick_count += 1
            is_attack_wave = (self.tick_count % self.attack_interval) == 0

            if is_attack_wave:
                current_atk = attack_types[attack_idx % len(attack_types)]
                attack_idx += 1
                flow = self.generate_attack_flow(current_atk)
                flow_type_label = f"{Colors.RED}{Colors.BOLD}[ATTACK: {current_atk.upper()}]{Colors.RESET}"
            else:
                flow = self.generate_normal_flow()
                flow_type_label = f"{Colors.GREEN}[NORMAL BASELINE]{Colors.RESET}"

            # Dispatch flow to RAKSHA backend
            res = self.send_flow(flow)
            bdi = res.get("bdi_score", 0.0)
            status = res.get("status", "UNKNOWN")
            is_anom = res.get("is_anomaly", False)

            # Color formatting based on threat status
            if status == "CRITICAL_ANOMALY" or is_anom:
                status_color = f"{Colors.RED}{Colors.BOLD}{status}{Colors.RESET}"
                bdi_color = f"{Colors.RED}{Colors.BOLD}BDI: {bdi:.2f}{Colors.RESET}"
            elif status == "SUSPICIOUS":
                status_color = f"{Colors.YELLOW}{status}{Colors.RESET}"
                bdi_color = f"{Colors.YELLOW}BDI: {bdi:.2f}{Colors.RESET}"
            else:
                status_color = f"{Colors.GREEN}{status}{Colors.RESET}"
                bdi_color = f"{Colors.GREEN}BDI: {bdi:.2f}{Colors.RESET}"

            src_host = self.assets.get(flow["src_ip"], {}).get("hostname") or self.adversaries.get(flow["src_ip"], {}).get("alias") or flow["src_ip"]
            dst_host = self.assets.get(flow["dst_ip"], {}).get("hostname") or flow["dst_ip"]

            timestamp_str = time.strftime("%H:%M:%S")
            print(f"[{timestamp_str}] Tick #{self.tick_count:04d} | {flow_type_label} | {flow['src_ip']:15s} ({src_host:16s}) -> {flow['dst_ip']:14s} ({dst_host:18s}) : {flow['dst_port']:<5d} | {bdi_color} | {status_color}")

            if res.get("error"):
                print(f"       {Colors.YELLOW}[!] Backend warning: {res['error']}{Colors.RESET}")

            time.sleep(self.interval)


def main():
    parser = argparse.ArgumentParser(description="RAKSHA-AI Multi-Subnet Live IP Telemetry Generator")
    parser.add_argument("--backend", default=os.getenv("BACKEND_URL", "http://localhost:8000"), help="Backend URL (default: http://localhost:8000)")
    parser.add_argument("--interval", type=float, default=float(os.getenv("STREAM_INTERVAL", "0.8")), help="Seconds between telemetry flow ticks (default: 0.8)")
    parser.add_argument("--attack-interval", type=int, default=int(os.getenv("ATTACK_INTERVAL", "15")), help="Inject an attack wave every N ticks (default: 15)")
    args = parser.parse_args()

    generator = TelemetryStreamGenerator(
        backend_url=args.backend,
        interval=args.interval,
        attack_interval=args.attack_interval
    )
    try:
        generator.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Telemetry stream stopped by operator.{Colors.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
