"""
host_backend.py
---------------------------------------
Sentinel-AI Host Firewall Backend (Zero-Hardware Mode)

Supports local OS firewall enforcement without any external switch:
- Linux: iptables / nftables
- Windows: netsh advfirewall / PowerShell
- Non-root / Unprivileged fallback: In-memory simulation with clean warnings.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from typing import List, Set

logger = logging.getLogger(__name__)


class HostFirewallBackend:
    """Zero-hardware local OS firewall driver."""

    CHAIN_NAME = "NIDS_DROP"
    RULE_PREFIX = "NIDS_BLOCK_"

    def __init__(self):
        self.os_type = platform.system().lower()  # 'linux', 'windows', 'darwin'
        self.logger = logger
        self._memory_blocks: Set[str] = set()
        self._is_privileged = self._check_privileges()

    def _check_privileges(self) -> bool:
        if self.os_type == "linux":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        elif self.os_type == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        return False

    def is_connected(self) -> bool:
        return True

    def connect(self, force: bool = False):
        return self

    def disconnect(self):
        pass

    def ensure_acl(self):
        """Initialize host firewall chain/rules."""
        if not self._is_privileged:
            logger.info("HostFirewall running in unprivileged user mode (in-memory tracking active)")
            return

        if self.os_type == "linux":
            try:
                # Check if NIDS_DROP chain exists
                check = subprocess.run(["iptables", "-N", self.CHAIN_NAME], capture_output=True, text=True)
                if check.returncode == 0:
                    # Created new chain, hook into INPUT
                    subprocess.run(["iptables", "-I", "INPUT", "1", "-j", self.CHAIN_NAME], capture_output=True)
            except Exception as e:
                logger.warning(f"Failed to initialize Linux iptables chain: {e}")

    def acl_exists(self) -> bool:
        return True

    def create_acl(self):
        self.ensure_acl()

    def get_blocked_ips(self) -> List[str]:
        """Return list of currently blocked IP addresses."""
        if not self._is_privileged:
            return sorted(self._memory_blocks)

        blocked: Set[str] = set(self._memory_blocks)

        if self.os_type == "linux":
            try:
                res = subprocess.run(["iptables", "-S", self.CHAIN_NAME], capture_output=True, text=True)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        match = re.search(r"-s\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?\s+-j\s+DROP", line)
                        if match:
                            blocked.add(match.group(1))
            except Exception as e:
                logger.warning(f"iptables read error: {e}")

        elif self.os_type == "windows":
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"],
                    capture_output=True, text=True
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if "Rule Name:" in line and self.RULE_PREFIX in line:
                            ip = line.split(self.RULE_PREFIX)[-1].strip()
                            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                                blocked.add(ip)
            except Exception as e:
                logger.warning(f"netsh read error: {e}")

        return sorted(blocked)

    def block(self, ip: str):
        """Block IP on the local OS firewall."""
        self._memory_blocks.add(ip)
        if not self._is_privileged:
            logger.info(f"[HostFirewall: In-Memory] Blocked IP: {ip}")
            return

        if self.os_type == "linux":
            try:
                # Add to NIDS_DROP chain
                subprocess.run(["iptables", "-I", self.CHAIN_NAME, "1", "-s", ip, "-j", "DROP"], capture_output=True)
                logger.info(f"[HostFirewall: iptables] Added DROP rule for {ip}")
            except Exception as e:
                logger.error(f"Failed to add iptables rule for {ip}: {e}")

        elif self.os_type == "windows":
            try:
                rule_name = f"{self.RULE_PREFIX}{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
                    capture_output=True
                )
                logger.info(f"[HostFirewall: netsh] Added block rule for {ip}")
            except Exception as e:
                logger.error(f"Failed to add Windows firewall rule for {ip}: {e}")

    def unblock(self, ip: str):
        """Remove IP block from local OS firewall."""
        self._memory_blocks.discard(ip)
        if not self._is_privileged:
            logger.info(f"[HostFirewall: In-Memory] Unblocked IP: {ip}")
            return

        if self.os_type == "linux":
            try:
                # Remove from NIDS_DROP chain
                subprocess.run(["iptables", "-D", self.CHAIN_NAME, "-s", ip, "-j", "DROP"], capture_output=True)
                logger.info(f"[HostFirewall: iptables] Removed DROP rule for {ip}")
            except Exception as e:
                logger.error(f"Failed to remove iptables rule for {ip}: {e}")

        elif self.os_type == "windows":
            try:
                rule_name = f"{self.RULE_PREFIX}{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True
                )
                logger.info(f"[HostFirewall: netsh] Removed rule for {ip}")
            except Exception as e:
                logger.error(f"Failed to remove Windows firewall rule for {ip}: {e}")

    def verify(self, ip: str) -> bool:
        return ip in self.get_blocked_ips()

    def verify_removed(self, ip: str) -> bool:
        return ip not in self.get_blocked_ips()
