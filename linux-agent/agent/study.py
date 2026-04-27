"""
study.py — Deep instance inspection (18+ categories) + Claude analysis.
"""
import json
import logging

from . import ssh as _ssh
from .core import _call_json

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SSH data collection commands
# ─────────────────────────────────────────────────────────────────────────────

STUDY_COMMANDS: dict[str, str] = {
    # Hardware
    "cpu_model": "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs 2>/dev/null",
    "cpu_cores": "grep -c '^processor' /proc/cpuinfo 2>/dev/null",
    "cpu_threads": "lscpu 2>/dev/null | grep '^Thread(s) per core' | awk '{print $NF}'",
    "cpu_flags": "grep flags /proc/cpuinfo | head -1 2>/dev/null",
    "ram_total": "awk '/MemTotal/{print $2\" kB\"}' /proc/meminfo 2>/dev/null",
    "ram_free": "awk '/MemAvailable/{print $2\" kB\"}' /proc/meminfo 2>/dev/null",
    "swap_total": "awk '/SwapTotal/{print $2\" kB\"}' /proc/meminfo 2>/dev/null",
    "disk_layout": "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null",
    "disk_usage": "df -h 2>/dev/null",
    # OS
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -r 2>/dev/null",
    "uptime": "uptime 2>/dev/null",
    "timezone": "timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null",
    "ntp_sync": "timedatectl show --property=NTPSynchronized --value 2>/dev/null",
    "pending_updates": (
        "( apt list --upgradable 2>/dev/null | grep -c upgradable || "
        "yum check-update 2>/dev/null | grep -c '\\.' ) 2>/dev/null || echo 0"
    ),
    "security_updates": (
        "( apt list --upgradable 2>/dev/null | grep -ci security || "
        "yum check-update --security 2>/dev/null | grep -c '\\.' ) 2>/dev/null || echo 0"
    ),
    # Services
    "running_services": "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null",
    "failed_services": "systemctl list-units --state=failed --no-pager --no-legend 2>/dev/null",
    "journal_errors": "journalctl -p err -n 40 --no-pager 2>/dev/null",
    "boot_errors": "journalctl -b -p err --no-pager -n 20 2>/dev/null",
    # Network
    "interfaces": "ip addr show 2>/dev/null",
    "routes": "ip route show 2>/dev/null",
    "dns": "cat /etc/resolv.conf 2>/dev/null",
    "open_ports": "ss -tlnp 2>/dev/null",
    "firewall_iptables": "iptables -L -n --line-numbers 2>/dev/null | head -60",
    "firewall_nftables": "nft list ruleset 2>/dev/null | head -60",
    "firewall_ufw": "ufw status verbose 2>/dev/null",
    "firewall_firewalld": "firewall-cmd --list-all 2>/dev/null",
    # Security
    "ssh_root_login": "grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
    "ssh_password_auth": "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null",
    "sudo_rules": "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'",
    "users": "awk -F: '$3>=1000{print $1, $3, $6, $7}' /etc/passwd 2>/dev/null",
    "suid_files": "find / -perm -4000 -type f 2>/dev/null | head -20",
    "selinux": "getenforce 2>/dev/null || echo not_installed",
    "apparmor": "apparmor_status 2>/dev/null | head -5 || aa-status 2>/dev/null | head -5 || echo not_installed",
    "failed_logins": "journalctl _SYSTEMD_UNIT=sshd.service 2>/dev/null | grep -i 'failed\\|invalid' | tail -10",
    # Software
    "python_version": "python3 --version 2>/dev/null || echo not_installed",
    "node_version": "node --version 2>/dev/null || echo not_installed",
    "java_version": "java -version 2>&1 | head -1 || echo not_installed",
    "go_version": "go version 2>/dev/null || echo not_installed",
    "docker_version": "docker --version 2>/dev/null || echo not_installed",
    "docker_containers": "docker ps -a 2>/dev/null | head -20",
    "k8s_version": "kubectl version --client 2>/dev/null | head -1 || echo not_installed",
    "nginx_version": "nginx -v 2>&1 || echo not_installed",
    "postgres_version": "psql --version 2>/dev/null || echo not_installed",
    "redis_version": "redis-server --version 2>/dev/null || echo not_installed",
    "ansible_version": "ansible --version 2>/dev/null | head -1 || echo not_installed",
    "terraform_version": "terraform version 2>/dev/null | head -1 || echo not_installed",
    # Performance
    "load_avg": "cat /proc/loadavg 2>/dev/null",
    "top_cpu_procs": "ps aux --sort=-%cpu 2>/dev/null | head -8",
    "top_mem_procs": "ps aux --sort=-%mem 2>/dev/null | head -8",
    "iostat": "iostat -x 1 1 2>/dev/null | head -20 || echo not_installed",
    # OpenStack environment
    "openstack_services": "openstack service list 2>/dev/null | head -30 || echo not_openstack",
    "openstack_hypervisors": "openstack hypervisor list 2>/dev/null | head -20 || echo not_openstack",
    "openstack_projects": "openstack project list 2>/dev/null | head -20 || echo not_openstack",
    "nova_compute_status": "systemctl is-active nova-compute 2>/dev/null || echo inactive",
    "neutron_status": "systemctl is-active neutron-openvswitch-agent 2>/dev/null || echo inactive",
    # Proxmox environment
    "pve_version": "pveversion 2>/dev/null || echo not_proxmox",
    "pve_nodes": "pvecm nodes 2>/dev/null || echo not_proxmox",
    "pve_vms": "qm list 2>/dev/null | head -20 || echo not_proxmox",
    "pve_cts": "pct list 2>/dev/null | head -20 || echo not_proxmox",
    # Kubernetes environment
    "k8s_nodes": "kubectl get nodes 2>/dev/null | head -20 || echo not_k8s",
    "k8s_namespaces": "kubectl get namespaces 2>/dev/null | head -20 || echo not_k8s",
    "k8s_deployments": "kubectl get deployments -A 2>/dev/null | head -20 || echo not_k8s",
    "k8s_pods": "kubectl get pods -A 2>/dev/null | head -30 || echo not_k8s",
    "k8s_pvcs": "kubectl get pvc -A 2>/dev/null | head -20 || echo not_k8s",
    # Docker Swarm
    "swarm_nodes": "docker node ls 2>/dev/null | head -20 || echo not_swarm",
    "docker_volumes": "docker volume ls 2>/dev/null | head -20",
    "docker_networks": "docker network ls 2>/dev/null | head -20",
    "compose_version": "docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo not_installed",
}


def collect_raw(instance: dict) -> dict:
    """SSH into instance and collect all study data. Returns dict of outputs."""
    raw: dict = {}
    for key, cmd in STUDY_COMMANDS.items():
        try:
            stdout, stderr, _ = _ssh.run_command(instance, cmd, timeout=30)
            raw[key] = stdout.strip() or stderr.strip()
        except Exception as exc:
            raw[key] = f"ERROR: {exc}"
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Claude analysis
# ─────────────────────────────────────────────────────────────────────────────

STUDY_SYSTEM = """You are an expert Linux infrastructure analyst.
Analyze all provided system data and return ONLY valid JSON (no markdown fences):
{
  "summary": {
    "headline": "<one-sentence overview>",
    "role": "<e.g. OpenStack Controller|Web Server|K8s Worker|General Linux>",
    "health_score": 85,
    "health_label": "Good|Fair|Poor|Critical",
    "key_findings": ["<finding1>", "<finding2>"]
  },
  "hardware": {
    "cpu_model": "<string>",
    "cores": 0,
    "threads": 0,
    "ram_gb": 0,
    "swap_gb": 0,
    "virtualization_support": true,
    "aes_support": true,
    "disk_summary": "<string>",
    "analysis": "<string>"
  },
  "os": {
    "name": "<string>",
    "kernel": "<string>",
    "uptime": "<string>",
    "timezone": "<string>",
    "ntp_synced": true,
    "pending_updates": 0,
    "security_updates": 0,
    "analysis": "<string>"
  },
  "services": {
    "total_running": 0,
    "total_failed": 0,
    "running": [{"name": "<svc>", "description": "<string>"}],
    "critical": ["<svc>"],
    "failed": ["<svc>"],
    "analysis": "<string>"
  },
  "network": {
    "interfaces": [{"name": "<string>", "addresses": ["<string>"]}],
    "open_ports": [{"port": 0, "service": "<string>", "exposure": "local|internet"}],
    "firewall": "<active|inactive|unknown>",
    "analysis": "<string>"
  },
  "security": {
    "score": 80,
    "label": "Good|Fair|Poor|Critical",
    "ssh_root_login": "<yes|no|unknown>",
    "password_auth": "<yes|no|unknown>",
    "firewall_active": true,
    "pending_security_updates": 0,
    "findings": [
      {"severity": "critical|high|medium|low", "issue": "<string>", "recommendation": "<string>"}
    ],
    "analysis": "<string>"
  },
  "software": {
    "installed_highlights": ["<pkg>"],
    "runtimes": ["<string>"],
    "databases": ["<string>"],
    "analysis": "<string>"
  },
  "environment": {
    "type": "openstack|proxmox|kubernetes|docker|bare-metal",
    "details": {},
    "analysis": "<string>"
  },
  "performance": {
    "cpu_load_1m": 0.0,
    "cpu_load_5m": 0.0,
    "cpu_load_15m": 0.0,
    "top_cpu_processes": ["<proc>"],
    "top_mem_processes": ["<proc>"],
    "analysis": "<string>"
  },
  "recommendations": [
    {
      "priority": "critical|high|medium|low",
      "category": "<string>",
      "title": "<string>",
      "detail": "<string>",
      "command": "<optional shell command>"
    }
  ]
}"""


def analyze(instance: dict, raw: dict) -> dict:
    """Send raw SSH data to Claude and return structured study report."""
    content = (
        f"Instance: {instance.get('label')} ({instance.get('host')})\n\n"
        f"Raw system data:\n{json.dumps(raw, indent=2)}"
    )
    messages = [{"role": "user", "content": content}]
    return _call_json(STUDY_SYSTEM, messages)


def run_study(instance: dict) -> tuple[dict, dict]:
    """
    Full study: collect raw data then analyse with Claude.
    Returns (report_json, raw_json).
    """
    raw = collect_raw(instance)
    report = analyze(instance, raw)
    return report, raw
