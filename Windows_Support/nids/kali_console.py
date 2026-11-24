"""Lightweight Kali Linux Console manager (Live SSH + Safe Demo Simulator)."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from collectors.suricata_parser import SuricataFlow

PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "nmap_syn",
        "name": "Nmap SYN Scan",
        "category": "Reconnaissance",
        "description": "Fast half-open TCP port scan against target host",
        "command": "nmap -sS -T4 -p 21,22,80,443,3306 {target}",
        "attack_type": "TCP Port Scan",
        "severity": "Medium",
        "dest_port": 22,
    },
    {
        "id": "hydra_ssh",
        "name": "Hydra SSH Brute Force",
        "category": "Brute Force",
        "description": "Dictionary attack against SSH service (port 22)",
        "command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target}",
        "attack_type": "SSH Brute Force",
        "severity": "High",
        "dest_port": 22,
    },
    {
        "id": "hping3_dos",
        "name": "HPing3 SYN Flood",
        "category": "DoS",
        "description": "High-rate SYN flood toward target HTTP port",
        "command": "hping3 -S -p 80 --flood {target}",
        "attack_type": "Denial of Service",
        "severity": "Critical",
        "dest_port": 80,
    },
    {
        "id": "sqli_probe",
        "name": "SQL Injection Probe",
        "category": "Web Attack",
        "description": "Send SQLi test payload to web endpoint",
        "command": "curl -s \"http://{target}/login?user=' OR 1=1--\"",
        "attack_type": "SQL Injection",
        "severity": "Critical",
        "dest_port": 80,
    },
]


class KaliConsoleManager:
    """Manages Kali connection state and command execution for the Console page."""

    def __init__(self, pipeline: Any = None) -> None:
        self.pipeline = pipeline
        self.connected = False
        self.mode = "simulation"  # "ssh" or "simulation"
        self.host = "192.168.56.101"
        self.port = 22
        self.username = "kali"
        self._password = ""
        self._ssh_client: Any = None
        self.history: list[dict[str, Any]] = []

    def status(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "history": self.history[-20:],
        }

    def connect(self, data: dict[str, Any]) -> dict[str, Any]:
        self.host = str(data.get("host") or "192.168.56.101").strip()
        self.port = int(data.get("port") or 22)
        self.username = str(data.get("username") or "kali").strip()
        self._password = str(data.get("password") or "")
        requested_mode = str(data.get("mode") or "simulation").lower()

        if requested_mode == "ssh":
            try:
                import paramiko  # optional dependency

                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self._password or None,
                    timeout=5.0,
                )
                self._close_ssh()
                self._ssh_client = client
                self.mode = "ssh"
                self.connected = True
                return {"success": True, "message": f"Connected to Kali SSH ({self.username}@{self.host}:{self.port})", **self.status()}
            except ImportError:
                if shutil.which("ssh"):
                    self.mode = "ssh_cli"
                    self.connected = True
                    return {"success": True, "message": f"Ready via system SSH ({self.username}@{self.host})", **self.status()}
                return {"success": False, "message": "Paramiko is not installed; switch to Demo Simulator or install paramiko."}
            except Exception as exc:
                self.connected = False
                return {"success": False, "message": f"SSH connection failed: {exc}"}

        self._close_ssh()
        self.mode = "simulation"
        self.connected = True
        return {"success": True, "message": f"Connected in Demo Simulator mode ({self.username}@{self.host})", **self.status()}

    def disconnect(self) -> dict[str, Any]:
        self._close_ssh()
        self.connected = False
        return {"success": True, "message": "Disconnected from Kali Console", **self.status()}

    def _close_ssh(self) -> None:
        if self._ssh_client is not None:
            try:
                self._ssh_client.close()
            except Exception:
                pass
            self._ssh_client = None

    def execute(self, command: str, target: str = "192.168.56.10") -> dict[str, Any]:
        cmd = command.strip()
        if not self.connected:
            return {"success": False, "stdout": "", "stderr": "Not connected. Click Connect first.", "exit_code": 1}
        if not cmd:
            return {"success": False, "stdout": "", "stderr": "Empty command.", "exit_code": 1}

        now = datetime.now(timezone.utc).isoformat()
        if self.mode == "ssh" and self._ssh_client is not None:
            try:
                _, stdout, stderr = self._ssh_client.exec_command(cmd, timeout=20)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                code = stdout.channel.recv_exit_status()
                entry = {"command": cmd, "stdout": out, "stderr": err, "exit_code": code, "timestamp": now}
                self.history.append(entry)
                return {"success": code == 0, **entry}
            except Exception as exc:
                return {"success": False, "command": cmd, "stdout": "", "stderr": str(exc), "exit_code": 1, "timestamp": now}

        if self.mode == "ssh_cli":
            try:
                proc = subprocess.run(
                    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", str(self.port), f"{self.username}@{self.host}", cmd],
                    capture_output=True, text=True, timeout=20,
                )
                entry = {"command": cmd, "stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode, "timestamp": now}
                self.history.append(entry)
                return {"success": proc.returncode == 0, **entry}
            except Exception as exc:
                return {"success": False, "command": cmd, "stdout": "", "stderr": str(exc), "exit_code": 1, "timestamp": now}

        # Demo Simulator mode: realistic output + live NIDS pipeline trigger
        out, pb = self._simulate_output(cmd, target)
        if pb and self.pipeline is not None:
            self._emit_simulated_attack(pb, target)

        entry = {"command": cmd, "stdout": out, "stderr": "", "exit_code": 0, "timestamp": now}
        self.history.append(entry)
        return {"success": True, **entry}

    def _simulate_output(self, cmd: str, target: str) -> tuple[str, dict[str, Any] | None]:
        low = cmd.lower()
        if "nmap" in low:
            pb = PLAYBOOKS[0]
            return (
                f"Starting Nmap 7.94 ( https://nmap.org )\n"
                f"Nmap scan report for {target}\n"
                f"Host is up (0.0012s latency).\n"
                f"PORT     STATE SERVICE\n"
                f"21/tcp   open  ftp\n"
                f"22/tcp   open  ssh\n"
                f"80/tcp   open  http\n"
                f"443/tcp  open  https\n"
                f"3306/tcp closed mysql\n"
                f"Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds\n",
                pb,
            )
        if "hydra" in low:
            pb = PLAYBOOKS[1]
            return (
                f"Hydra v9.5 starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"[DATA] attacking ssh://{target}:22/\n"
                f"[ATTEMPT] target {target} - login \"admin\" - pass \"123456\"\n"
                f"[ATTEMPT] target {target} - login \"admin\" - pass \"password\"\n"
                f"[STATUS] 120.00 tries/min — NIDS alert triggered!\n",
                pb,
            )
        if "hping3" in low or "flood" in low:
            pb = PLAYBOOKS[2]
            return (
                f"HPING {target} (eth0 {target}): S set, 40 headers + 0 data bytes\n"
                f"hping in flood mode, no replies will be shown\n"
                f"--- {target} hping statistic ---\n"
                f"2500 packets transmitted, 0 packets received, 100% packet loss\n",
                pb,
            )
        if "curl" in low or "sql" in low or "or 1=1" in low:
            pb = PLAYBOOKS[3]
            return (
                f"GET http://{target}/login?user=' OR 1=1-- HTTP/1.1\n"
                f"HTTP/1.1 403 Forbidden (Blocked / Logged by Sentinel-AI NIDS)\n",
                pb,
            )
        return f"[{self.username}@kali] $ {cmd}\nCommand executed in demo sandbox.\n", None

    def _emit_simulated_attack(self, pb: dict[str, Any], target: str) -> None:
        now = datetime.now(timezone.utc)
        sig_map = {
            "TCP Port Scan": "ET SCAN Nmap TCP SYN scan",
            "SSH Brute Force": "ET SCAN Potential SSH Brute Force",
            "Denial of Service": "ET DOS Potential SYN Flood",
            "SQL Injection": "ET WEB_SERVER SQL Injection Attempt",
        }
        flow = SuricataFlow(
            timestamp=now,
            src_ip=self.host,
            dest_ip=target,
            src_port=54321,
            dest_port=int(pb.get("dest_port", 80)),
            proto="TCP",
            bytes_toserver=1800,
            bytes_toclient=120,
            pkts_toserver=45,
            pkts_toclient=2,
            flow_start=now,
            flow_end=now,
            alert_signature=sig_map.get(pb["attack_type"], pb["attack_type"]),
            alert_severity=2,
            raw_event={"source": "kali_console", "playbook": pb["id"], "alert": {"signature_id": 990001}},
        )
        self.pipeline.process_flow(flow)
