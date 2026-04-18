#!/usr/bin/env bash
set -e

# ── Linux AI Agent startup script ──────────────────────────────────────────

# Require Python 3
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Please install Python 3." >&2
  exit 1
fi

# Prompt for API key if not set
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo -n "Enter your Anthropic API key: "
  read -rs ANTHROPIC_API_KEY
  echo
  if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ERROR: ANTHROPIC_API_KEY is required." >&2
    exit 1
  fi
  export ANTHROPIC_API_KEY
  # Persist to ~/.bashrc so future shells pick it up automatically
  grep -qxF "export ANTHROPIC_API_KEY=\"${ANTHROPIC_API_KEY}\"" ~/.bashrc 2>/dev/null \
    || echo "export ANTHROPIC_API_KEY=\"${ANTHROPIC_API_KEY}\"" >> ~/.bashrc
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ">> Installing dependencies…"
pip3 install -q -r requirements.txt

echo ">> Preparing directories…"
mkdir -p data
touch agent/__init__.py

echo ">> Starting Linux AI Agent on http://0.0.0.0:7070 …"
PYTHONPATH="$SCRIPT_DIR" python3 web/server.py
