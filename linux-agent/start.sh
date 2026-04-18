#!/usr/bin/env bash
set -e

# ── prerequisite check ────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is not installed. Please install Python 3.9+ and re-run."
  exit 1
fi

# ── Anthropic API key ─────────────────────────────────────────────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
  read -rsp "Enter your ANTHROPIC_API_KEY: " ANTHROPIC_API_KEY
  echo
  export ANTHROPIC_API_KEY
  echo "export ANTHROPIC_API_KEY=\"$ANTHROPIC_API_KEY\"" >> ~/.bashrc
  echo "API key saved to ~/.bashrc"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── install dependencies ──────────────────────────────────────────────────────
echo "Installing Python dependencies …"
pip3 install -q -r requirements.txt

# ── prepare runtime directories ───────────────────────────────────────────────
mkdir -p data
touch agent/__init__.py

# ── launch ────────────────────────────────────────────────────────────────────
echo "Starting Linux AI Infrastructure Agent on http://0.0.0.0:7070 …"
exec python3 web/server.py
