#!/usr/bin/env bash
# install-service.sh — Install the Linux AI Agent as a systemd service.
# Run once as root (or with sudo) after cloning the repository.
# Usage:  sudo bash linux-agent/install-service.sh
set -e

SERVICE_NAME="linux-ai-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT=7070

# ── require root ──────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root: sudo bash $0"
  exit 1
fi

# ── detect script location ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── python check ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is not installed. Please install Python 3.9+ and re-run."
  exit 1
fi

# ── collect OPENAI_API_KEY ────────────────────────────────────────────────────
if [ -z "$OPENAI_API_KEY" ]; then
  read -rsp "Enter your OPENAI_API_KEY: " OPENAI_API_KEY
  echo
fi

# ── determine the user that should own the service ───────────────────────────
DEFAULT_USER="${SUDO_USER:-$USER}"
read -rp "Run service as which user? [${DEFAULT_USER}]: " SERVICE_USER
SERVICE_USER="${SERVICE_USER:-$DEFAULT_USER}"

# Validate the user actually exists on this system
if ! id -u "$SERVICE_USER" &>/dev/null; then
  echo "WARNING: User '${SERVICE_USER}' does not exist on this system."
  echo "         Falling back to 'root'. Re-run and specify a valid user to change this."
  SERVICE_USER="root"
fi

# ── virtual environment ───────────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment …"
  python3 -m venv "$VENV_DIR"
fi

echo "Installing Python dependencies …"
"$VENV_DIR/bin/pip" install -q --upgrade pip
"$VENV_DIR/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"

mkdir -p "$SCRIPT_DIR/data"
touch "$SCRIPT_DIR/agent/__init__.py"

# ── write systemd unit file ───────────────────────────────────────────────────
# When running as root, omit "User=" entirely.  Explicitly setting User=root
# triggers a getpwnam("root") NSS lookup that can fail on containers or
# minimal systems, producing status=217/USER even though root always exists.
if [ "$SERVICE_USER" = "root" ]; then
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux AI Infrastructure Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
Environment="OPENAI_API_KEY=${OPENAI_API_KEY}"
ExecStart=${VENV_DIR}/bin/python ${SCRIPT_DIR}/web/server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
else
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux AI Infrastructure Agent
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${SCRIPT_DIR}
Environment="OPENAI_API_KEY=${OPENAI_API_KEY}"
ExecStart=${VENV_DIR}/bin/python ${SCRIPT_DIR}/web/server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
fi

echo "Wrote ${SERVICE_FILE}"

# ── open firewall port ────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
  echo "Opening port ${PORT}/tcp in ufw …"
  ufw allow "${PORT}/tcp" > /dev/null
elif command -v firewall-cmd &>/dev/null; then
  echo "Opening port ${PORT}/tcp in firewalld …"
  firewall-cmd --permanent --add-port="${PORT}/tcp" > /dev/null
  firewall-cmd --reload > /dev/null
else
  echo "NOTE: No ufw or firewalld found. If a firewall is active, open port ${PORT}/tcp manually."
fi

# ── enable and start ──────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# ── verify it came up ─────────────────────────────────────────────────────────
sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
  # Determine the best IP to show
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  SERVER_IP="${SERVER_IP:-localhost}"

  echo ""
  echo "✅  Service '${SERVICE_NAME}' is running."
  echo "    Open in browser : http://${SERVER_IP}:${PORT}"
  echo ""
  echo "    Check status : sudo systemctl status ${SERVICE_NAME}"
  echo "    View logs    : sudo journalctl -u ${SERVICE_NAME} -f"
  echo "    Stop         : sudo systemctl stop ${SERVICE_NAME}"
  echo "    Uninstall    : sudo systemctl disable --now ${SERVICE_NAME} && sudo rm ${SERVICE_FILE}"
else
  echo ""
  echo "❌  Service failed to start. Last 20 log lines:"
  journalctl -u "$SERVICE_NAME" -n 20 --no-pager
  echo ""
  echo "Fix the error above, then run:  sudo systemctl restart ${SERVICE_NAME}"
  exit 1
fi
