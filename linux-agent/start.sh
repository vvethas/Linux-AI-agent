#!/usr/bin/env bash
set -e

# ── prerequisite check ────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is not installed. Please install Python 3.9+ and re-run."
  exit 1
fi

# ── OpenAI API key ────────────────────────────────────────────────────────────
if [ -z "$OPENAI_API_KEY" ]; then
  read -rsp "Enter your OPENAI_API_KEY: " OPENAI_API_KEY
  echo
  export OPENAI_API_KEY
  echo "export OPENAI_API_KEY=\"$OPENAI_API_KEY\"" >> ~/.bashrc
  echo "API key saved to ~/.bashrc"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── virtual environment ───────────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment …"
  python3 -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# ── install dependencies ──────────────────────────────────────────────────────
echo "Installing Python dependencies …"
pip install -q --upgrade pip
pip install -q -r requirements.txt

# ── prepare runtime directories ───────────────────────────────────────────────
mkdir -p data
touch agent/__init__.py

# ── launch ────────────────────────────────────────────────────────────────────
echo "Starting Linux AI Infrastructure Agent on http://0.0.0.0:7070 …"
exec python web/server.py
