"""
backend.py
---------------------------------------
Sentinel-AI Cisco Backend

Handles all Cisco IOS communication.
"""

import re

try:  # package import used by the integrated service
    from .config import CiscoConfig
    from .logger import EngineLogger
except ImportError:  # direct legacy execution from response_engine/
    from config import CiscoConfig
    from logger import EngineLogger


class CiscoBackend:

    def __init__(self):

        self.logger = EngineLogger()

        self.connection = None

        self.device = {

            "device_type": CiscoConfig.DEVICE_TYPE,

            "host": CiscoConfig.HOST,

            "username": CiscoConfig.USERNAME,

            "password": CiscoConfig.PASSWORD,

            "secret": CiscoConfig.SECRET,

            "timeout": CiscoConfig.CONNECTION_TIMEOUT,

            "fast_cli": CiscoConfig.FAST_CLI,
        }

    # =====================================================

    def is_connected(self):
        if not self.connection:
            return False
        try:
            return bool(self.connection.is_alive())
        except Exception:
            return False

    # =====================================================

    def connect(self, force=False):
        if not force and self.is_connected():
            return self.connection

        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None

        if not self.device["host"] or not self.device["username"]:
            raise RuntimeError(
                "Cisco connection is not configured; set NIDS_CISCO_HOST and NIDS_CISCO_USERNAME "
                "only in an approved enforcement environment."
            )

        try:
            from netmiko import ConnectHandler
            from netmiko.exceptions import (
                NetmikoAuthenticationException,
                NetmikoTimeoutException,
            )
        except ImportError as exc:
            raise RuntimeError("Netmiko is required for non-dry-run Cisco enforcement") from exc

        try:
            self.connection = ConnectHandler(**self.device)
            self.connection.enable()
            self.logger.connection(CiscoConfig.HOST)
            return self.connection
        except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        ) as ex:
            self.logger.exception(ex)
            self.connection = None
            raise

    # =====================================================

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.logger.disconnect()
            self.connection = None

    # =====================================================

    def get_blocked_ips(self):
        for attempt in range(2):
            try:
                conn = self.connect()
                output = conn.send_command(
                    f"show access-lists {CiscoConfig.ACL_NAME}",
                    read_timeout=6,
                )
                pattern = r"deny ip host (\d+\.\d+\.\d+\.\d+) any"
                blocked = []
                for line in output.splitlines():
                    result = re.search(pattern, line)
                    if result:
                        blocked.append(result.group(1))
                return blocked
            except Exception as ex:
                self.logger.exception(ex)
                self.disconnect()
                if attempt == 1:
                    return []

    # =====================================================

    def rebuild_acl(self, blocked_ips):
        # NOTE: Full ACL rebuild — the entire IDS-BLOCK ACL is deleted and
        # recreated on every block/unblock operation.  Two important risks:
        #   1. If the process is interrupted mid-rebuild (crash, network blip,
        #      Cisco SSH timeout) the ACL is left in a partially-built or
        #      absent state, briefly unblocking all IPs until the next call.
        #   2. Any rules manually added to IDS-BLOCK for other purposes will
        #      be silently wiped.  Do NOT add unrelated rules to IDS-BLOCK
        #      manually — use a separate ACL for anything this code doesn't own.
        commands = [
            f"no ip access-list extended {CiscoConfig.ACL_NAME}",
            f"ip access-list extended {CiscoConfig.ACL_NAME}",
        ]
        for ip in sorted(set(blocked_ips)):
            commands.append(f"deny ip host {ip} any")
        commands.append("permit ip any any")

        for attempt in range(2):
            try:
                conn = self.connect()
                conn.send_config_set(commands, read_timeout=8)
                return
            except Exception as ex:
                self.logger.exception(ex)
                self.disconnect()
                if attempt == 1:
                    raise

    # =====================================================

    def block(self, ip):

        blocked = self.get_blocked_ips()

        if ip not in blocked:

            blocked.append(ip)

            self.rebuild_acl(blocked)

            self.logger.block(ip)

    # =====================================================

    def unblock(self, ip):

        blocked = self.get_blocked_ips()

        if ip in blocked:

            blocked.remove(ip)

            self.rebuild_acl(blocked)

            self.logger.unblock(ip)

    # =====================================================

    def verify(self, ip):

        blocked = self.get_blocked_ips()

        return ip in blocked

    # =====================================================

    def verify_removed(self, ip):

        blocked = self.get_blocked_ips()

        return ip not in blocked

    # =====================================================

    def acl_exists(self):

        conn = self.connect()

        output = conn.send_command(

            "show access-lists"

        )

        return CiscoConfig.ACL_NAME in output

    # =====================================================

    def create_acl(self):

        conn = self.connect()

        commands = [

            f"ip access-list extended {CiscoConfig.ACL_NAME}",

            "permit ip any any",

        ]

        conn.send_config_set(commands)

    # =====================================================

    def ensure_acl(self):

        if not self.acl_exists():

            self.create_acl()
