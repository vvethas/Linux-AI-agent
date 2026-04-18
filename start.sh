#!/usr/bin/env bash
set -e

# ── Linux AI Agent startup script ──────────────────────────────────────────

# Require Python 3
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Please install Python 3." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Load existing .env if present
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
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
  # Persist to a dedicated .env file with owner-only read permissions
  printf 'export ANTHROPIC_API_KEY="%s"\n' "$ANTHROPIC_API_KEY" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo ">> API key saved to ${ENV_FILE} (permissions: 600)"
fi

cd "$SCRIPT_DIR"

echo ">> Installing dependencies…"
pip3 install -q -r requirements.txt

echo ">> Preparing directories…"
mkdir -p data
touch agent/__init__.py

echo ">> Starting Linux AI Agent on http://0.0.0.0:7070 …"
PYTHONPATH="$SCRIPT_DIR" python3 web/server.py
