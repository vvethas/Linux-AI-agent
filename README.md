# Linux-AI-agent
AI Agent for linux.

## Quick start (foreground)

```bash
bash linux-agent/start.sh
```

## Run as a background systemd service (survives Ctrl+C and reboots)

```bash
sudo bash linux-agent/install-service.sh
```

The script will:
1. Ask for your `OPENAI_API_KEY` and which user should own the process.
2. Create a Python virtual environment and install dependencies.
3. Write `/etc/systemd/system/linux-ai-agent.service` and start it immediately.

### Useful commands after installation

| Action | Command |
|--------|---------|
| Check status | `sudo systemctl status linux-ai-agent` |
| View live logs | `sudo journalctl -u linux-ai-agent -f` |
| Stop | `sudo systemctl stop linux-ai-agent` |
| Restart | `sudo systemctl restart linux-ai-agent` |
| Uninstall | `sudo systemctl disable --now linux-ai-agent && sudo rm /etc/systemd/system/linux-ai-agent.service` |

After a `git pull` to update the code, restart the service to pick up changes:

```bash
sudo systemctl restart linux-ai-agent
```
