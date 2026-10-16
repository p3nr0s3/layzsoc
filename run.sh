#!/usr/bin/env bash
# LazySOC startup script for Linux and macOS
set -e

echo "==================================================="
echo "  Starting LazySOC Threat Triage & SOC Workbench..."
echo "==================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment if present
if [ -d ".venv" ]; then
    echo "[*] Activating virtual environment (.venv)..."
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source venv/bin/activate
fi

# Check Python availability
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "[!] Error: Python 3 is required but was not found in PATH."
    exit 1
fi

PY_BIN="$(command -v python3 || command -v python)"

# Execute server
exec "$PY_BIN" server.py
