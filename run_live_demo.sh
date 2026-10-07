#!/usr/bin/env bash
# ==============================================================================
# AEGIS-AI: Live Multi-Subnet IP Telemetry Simulation Runner
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================================================="
echo "   PROJECT AEGIS-AI: LIVE MULTI-SUBNET IP SIMULATION RUNNER"
echo "=============================================================================="

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "[+] Docker Compose detected! Launching all 3 containers:"
    echo "    1. aegis-backend           (FastAPI + ML Anomaly Engine on :8000)"
    echo "    2. aegis-frontend          (Next.js SOC Dashboard on :3000)"
    echo "    3. aegis-traffic-generator (Live Multi-Subnet IP Probe)"
    echo ""
    docker compose up --build
else
    echo "[!] Docker is not installed or not running on this host."
    echo "[*] Falling back to Direct Python Mode:"
    echo ""
    echo "    To test the live IP simulation probe right now:"
    echo "    1. In Terminal A (Backend):"
    echo "       /home/sameer/.gemini/antigravity-ide/scratch/Aegis.ai/.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
    echo "    2. In Terminal B (Frontend):"
    echo "       cd frontend && npm run dev"
    echo "    3. In Terminal C (Live IP Generator):"
    echo "       python3 docker/generator/traffic_generator.py --backend http://localhost:8000"
    echo ""
    echo "[*] Launching traffic generator against http://localhost:8000..."
    python3 "$SCRIPT_DIR/docker/generator/traffic_generator.py" --backend http://localhost:8000
fi
