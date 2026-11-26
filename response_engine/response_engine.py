"""
response_engine.py
---------------------------------------
Sentinel-AI Response Engine

Fixes applied vs. the original version:
  1. self.lock is now an RLock (not Lock) so temp_block_ip can safely
     wrap block_ip without deadlocking or leaving a race window.
  2. __init__ no longer touches the network. All device access
     (ensure_acl / connect / sync from switch) happens in startup(),
     wrapped in try/except, so a dead switch never crashes object
     creation.
  3. All backend calls are wrapped (_apply_backend) so a Netmiko
     exception turns into a normal failed ActionResult instead of an
     uncaught exception bubbling up to the caller.
  4. Fixed stats bug: temporary blocks no longer also increment
     permanent_blocks.
  5. EngineConfig.VERIFY_AFTER_ACTION, DRY_RUN, AUTO_CREATE_ACL,
     VERIFY_CONNECTION_ON_STARTUP, MAX_HISTORY_SIZE, ENABLE_ACTION_HISTORY
     and AUTO_SAVE_HISTORY are now actually honored (previously defined
     in config.py but never read anywhere).
  6. add_to_whitelist / remove_from_whitelist are now lock-protected.
  7. _validate_ip is restricted to IPv4, matching what the Cisco
     backend can actually enforce (IPv6 addresses used to pass
     validation but could never really be blocked).
  8. get_stats() now reports a real uptime_seconds and total_errors
     is actually incremented on failures.
"""

import json
import threading
import uuid
import ipaddress
import time

from datetime import datetime, timedelta

try:  # package import used by the integrated service
    from .backend import CiscoBackend
    from .logger import EngineLogger
    from . import config as _re_config
    from .config import EngineConfig, Messages
    from .models import ActionResult, BlockedIP, EngineStats
except ImportError:  # direct legacy execution from response_engine/
    from backend import CiscoBackend
    from logger import EngineLogger
    import config as _re_config
    from config import EngineConfig, Messages
    from models import ActionResult, BlockedIP, EngineStats


class ResponseEngine:

    def __init__(self, on_event=None, backend=None):

        self.backend = backend if backend is not None else CiscoBackend()

        self.logger = EngineLogger()

        # RLock, not Lock: temp_block_ip needs to call block_ip while
        # already holding the lock itself, on the same thread.
        self.lock = threading.RLock()

        self.active_blocks = {}

        self.active_timers = {}

        self.stats = EngineStats()

        # Buffer for history entries when AUTO_SAVE_HISTORY is False
        self._pending_history = []

        self._start_time = time.time()

        # Optional callback: on_event(action_result_dict) is invoked
        # every time block_ip/unblock_ip completes (including when an
        # auto-unblock timer fires). Lets an external layer such as a
        # WebSocket server push real-time updates to a dashboard
        # without polling. Called from whatever thread performed the
        # action (a caller's thread, or the Timer thread) - the
        # callback itself must be thread-safe.
        self.on_event = on_event

        # NOTE: no backend/network calls here. That all happens in
        # startup(), so building a ResponseEngine() can never raise
        # just because the switch happens to be unreachable.

    # =====================================================

    def _sync_from_switch(self):
        """Reconcile in-memory state with persisted temp blocks and live switch ACL.
        In DRY_RUN mode, backend.get_blocked_ips() raises because there's no
        Cisco connection — that is silently caught and blocked stays empty,
        which is correct: no live ACL to read.
        """
        try:
            blocked = self.backend.get_blocked_ips()
        except Exception:
            blocked = []

        persisted_temp = self._load_temp_blocks()
        now = time.time()
        active_temp_to_save = {}

        # Reconcile persisted temporary blocks
        for ip, info in list(persisted_temp.items()):
            expires_epoch = info.get("expires_epoch")
            if expires_epoch and expires_epoch <= now:
                # Expired while offline -> unblock on switch if still present
                if ip in blocked:
                    try:
                        self.backend.unblock(ip)
                    except Exception as ex:
                        self.logger.exception(ex)
            elif expires_epoch and expires_epoch > now:
                # Still active -> re-arm timer and register as temporary block
                remaining = max(1.0, expires_epoch - now)
                self.active_blocks[ip] = BlockedIP(
                    ip=ip,
                    block_type="temporary",
                    reason=info.get("attack", ""),
                    timeout=info.get("timeout"),
                    expires_at=info.get("expires_at"),
                    expires_epoch=expires_epoch,
                )
                active_temp_to_save[ip] = info
                self._start_timer(ip, remaining)

        # Update persisted temp blocks on disk
        self._save_temp_blocks(active_temp_to_save)

        # Refresh switch state if any expired blocks were removed
        if active_temp_to_save != persisted_temp:
            try:
                blocked = self.backend.get_blocked_ips()
            except Exception:
                pass

        # Only classify switch entries without matching temp record as permanent
        for ip in blocked:
            if ip not in self.active_blocks:
                self.active_blocks[ip] = BlockedIP(
                    ip=ip,
                    block_type="permanent"
                )

    # =====================================================

    def _validate_ip(self, ip):

        # IPv4 only: the backend builds "ip access-list extended" /
        # "deny ip host X any" commands, which are IPv4-only. Accepting
        # IPv6 here would validate addresses that can never actually
        # be enforced on the device.
        try:

            ipaddress.IPv4Address(ip)

            return True

        except ValueError:

            return False

    # =====================================================

    def _timestamp(self):

        return datetime.now().isoformat()

    # =====================================================

    def _load_json(self, file_path, default):

        try:

            with open(file_path, "r") as f:

                return json.load(f)

        except Exception:

            return default

    # =====================================================

    def _save_json(self, file_path, data):

        with open(file_path, "w") as f:

            json.dump(
                data,
                f,
                indent=4
            )

    # =====================================================

    def _load_temp_blocks(self):
        return self._load_json(
            _re_config.TEMP_BLOCKS_FILE,
            {}
        )

    # =====================================================

    def _save_temp_blocks(self, temp_blocks):
        self._save_json(
            _re_config.TEMP_BLOCKS_FILE,
            temp_blocks
        )

    # =====================================================

    def _load_whitelist(self):

        return self._load_json(
            _re_config.WHITELIST_FILE,
            []
        )

    # =====================================================

    def _save_whitelist(self, whitelist):

        self._save_json(
            _re_config.WHITELIST_FILE,
            whitelist
        )

    # =====================================================

    def _load_history(self):

        on_disk = self._load_json(_re_config.ACTION_HISTORY_FILE, [])

        if not EngineConfig.AUTO_SAVE_HISTORY:

            return self._pending_history + on_disk

        return on_disk

    # =====================================================

    def _save_history(self, history):

        self._save_json(
            _re_config.ACTION_HISTORY_FILE,
            history
        )

    # =====================================================

    def _record_action(
        self,
        action,
        ip,
        success,
        verified,
        source,
        attack=None,
        severity=None,
        timeout=None
    ):

        if not EngineConfig.ENABLE_ACTION_HISTORY:

            return

        entry = {
            "id": str(uuid.uuid4()),
            "action": action,
            "ip": ip,
            "attack": attack,
            "severity": severity,
            "source": source,
            "timeout": timeout,
            "success": success,
            "verified": verified,
            "timestamp": self._timestamp()
        }

        if not EngineConfig.AUTO_SAVE_HISTORY:

            # Kept in memory only, persisted later via flush_history()
            self._pending_history.append(entry)

            return

        history = self._load_json(_re_config.ACTION_HISTORY_FILE, [])

        history.append(entry)

        if len(history) > EngineConfig.MAX_HISTORY_SIZE:

            history = history[-EngineConfig.MAX_HISTORY_SIZE:]

        self._save_history(history)

    # =====================================================

    def flush_history(self):
        """Persist any history entries buffered in memory. Only does
        real work when EngineConfig.AUTO_SAVE_HISTORY is False."""

        if not self._pending_history:

            return

        with self.lock:

            history = self._load_json(_re_config.ACTION_HISTORY_FILE, [])

            history.extend(self._pending_history)

            if len(history) > EngineConfig.MAX_HISTORY_SIZE:

                history = history[-EngineConfig.MAX_HISTORY_SIZE:]

            self._save_history(history)

            self._pending_history = []

    # =====================================================

    def get_history(self):

        return self._load_history()

    # =====================================================

    def get_whitelist(self):

        return self._load_whitelist()

    # =====================================================

    def add_to_whitelist(self, ip, source="Dashboard"):

        with self.lock:

            if not self._validate_ip(ip):

                return False

            whitelist = self._load_whitelist()

            if ip in whitelist:

                return False

            # FR-4.4: if this address is currently blocked (temporary or
            # permanent), the unblock must happen BEFORE the address is
            # added to the whitelist, as a single atomic operation under
            # self.lock, so the switch state and the whitelist can never
            # diverge (an address must never end up both "whitelisted"
            # and "still blocked on the switch").
            if ip in self.active_blocks:

                unblock_result = self.unblock_ip(ip, source=source)

                if not unblock_result.get("success"):

                    # Do NOT whitelist an address we failed to unblock -
                    # that would leave it blocked at the switch while the
                    # system believes it is protected.
                    return False

            whitelist.append(ip)

            self._save_whitelist(whitelist)

            return True

    # =====================================================

    def remove_from_whitelist(self, ip):

        with self.lock:

            whitelist = self._load_whitelist()

            if ip not in whitelist:

                return False

            whitelist.remove(ip)

            self._save_whitelist(whitelist)

            return True

    # =====================================================

    def get_active_blocks(self):

        return [

            block.to_dict()

            for block in self.active_blocks.values()

        ]

    # =====================================================

    def _emit(self, action_result):

        if self.on_event is None:

            return

        try:

            self.on_event(action_result)

        except Exception as ex:

            self.logger.exception(ex)

    # =====================================================

    def get_stats(self):

        self.stats.active_blocks = len(

            self.active_blocks

        )

        self.stats.whitelist_size = len(

            self.get_whitelist()

        )

        self.stats.uptime_seconds = int(

            time.time() - self._start_time

        )

        return self.stats.to_dict()

    # =====================================================

    def _apply_backend(self, action, ip):
        """
        Runs the real backend call for 'block' / 'unblock', wrapped so
        that a Netmiko/auth/timeout exception never escapes as a raw
        exception. Returns (ok, verified):

          ok       -> the backend call completed without raising
          verified -> the resulting device state matches expectations
                      (or is assumed true, if VERIFY_AFTER_ACTION is
                      disabled, or if DRY_RUN is on)
        """

        if EngineConfig.DRY_RUN:

            self.logger.info(f"[DRY RUN] {action} {ip}")

            return True, True

        try:

            if action == "block":

                self.backend.block(ip)

            else:

                self.backend.unblock(ip)

        except Exception as ex:

            self.logger.exception(ex)

            self.stats.total_errors += 1

            return False, False

        if not EngineConfig.VERIFY_AFTER_ACTION:

            return True, True

        try:

            if action == "block":

                verified = self.backend.verify(ip)

            else:

                verified = self.backend.verify_removed(ip)

            return True, verified

        except Exception as ex:

            self.logger.exception(ex)

            self.stats.total_errors += 1

            return False, False

    # =====================================================

    def block_ip(
        self,
        ip,
        attack=None,
        severity=None,
        source="Unknown",
        block_type="permanent",
        timeout=None
    ):

        with self.lock:

            if not self._validate_ip(ip):

                return ActionResult(
                    False,
                    "block",
                    ip,
                    Messages.INVALID_IP
                ).to_dict()

            if ip in self.get_whitelist():

                self.logger.whitelist(ip)

                return ActionResult(
                    False,
                    "block",
                    ip,
                    Messages.WHITELISTED
                ).to_dict()

            if ip in self.active_blocks:

                return ActionResult(
                    False,
                    "block",
                    ip,
                    Messages.ALREADY_BLOCKED
                ).to_dict()

            ok, verified = self._apply_backend("block", ip)

            if verified:
                expires_at = None
                expires_epoch = None
                if block_type == "temporary" and timeout:
                    expires_at = (datetime.now() + timedelta(seconds=int(timeout))).isoformat()
                    expires_epoch = time.time() + float(timeout)

                self.active_blocks[ip] = BlockedIP(
                    ip=ip,
                    block_type=block_type,
                    reason=attack or "",
                    timeout=timeout,
                    expires_at=expires_at,
                    expires_epoch=expires_epoch
                )

                if block_type == "temporary":
                    temp_blocks = self._load_temp_blocks()
                    temp_blocks[ip] = {
                        "ip": ip,
                        "attack": attack or "",
                        "severity": severity,
                        "source": source,
                        "timeout": timeout,
                        "created_at": self._timestamp(),
                        "expires_at": expires_at,
                        "expires_epoch": expires_epoch,
                    }
                    self._save_temp_blocks(temp_blocks)

                self.stats.total_blocks += 1

                if block_type == "temporary":

                    self.stats.temporary_blocks += 1

                else:

                    self.stats.permanent_blocks += 1

                self.stats.total_actions += 1

            self._record_action(
                action="block",
                ip=ip,
                success=verified,
                verified=verified,
                source=source,
                attack=attack,
                severity=severity,
                timeout=timeout
            )

            if not ok:

                result_message = Messages.CONNECTION_FAILED

            elif verified:

                result_message = Messages.BLOCK_SUCCESS

            else:

                result_message = Messages.VERIFICATION_FAILED

            action_result = ActionResult(
                verified,
                "block" if block_type != "temporary" else "temporary_block",
                ip,
                result_message,
                verified
            ).to_dict()

            action_result["source"] = source

            self._emit(action_result)

            return action_result

    # =====================================================

    def unblock_ip(
        self,
        ip,
        source="Dashboard"
    ):

        with self.lock:

            if not self._validate_ip(ip):

                return ActionResult(
                    False,
                    "unblock",
                    ip,
                    Messages.INVALID_IP
                ).to_dict()

            ok, verified = self._apply_backend("unblock", ip)

            self.active_blocks.pop(ip, None)

            temp_blocks = self._load_temp_blocks()
            if ip in temp_blocks:
                temp_blocks.pop(ip, None)
                self._save_temp_blocks(temp_blocks)

            timer = self.active_timers.pop(ip, None)

            if timer:

                timer.cancel()

            if verified:

                self.stats.total_actions += 1

            self._record_action(
                action="unblock",
                ip=ip,
                success=verified,
                verified=verified,
                source=source
            )

            if not ok:

                result_message = Messages.CONNECTION_FAILED

            elif verified:

                result_message = Messages.UNBLOCK_SUCCESS

            else:

                result_message = Messages.VERIFICATION_FAILED

            action_result = ActionResult(
                verified,
                "unblock",
                ip,
                result_message,
                verified
            ).to_dict()

            action_result["source"] = source

            self._emit(action_result)

            return action_result

    # =====================================================

    def _auto_unblock(self, ip):

        self.unblock_ip(
            ip,
            source="Auto Timer"
        )

    # =====================================================

    def _start_timer(
        self,
        ip,
        timeout
    ):

        timer = self.active_timers.get(ip)

        if timer:

            timer.cancel()

        timer = threading.Timer(
            timeout,
            self._auto_unblock,
            args=(ip,)
        )

        # عمدًا مش daemon: لو خليناه daemon وحصل crash في السكريبت
        # اللي بينادي الـ engine، بايثون هتقفل الـ thread فورًا حتى لو
        # كان قرّب يفك الحظر، وده يسيب IP محظور على الراوتر للأبد.
        # الأفضل إنه يكمل شغله ويفك الحظر مهما حصل، وإدارة إيقافه
        # بشكل نضيف بتبقى مسؤولية shutdown().
        timer.daemon = False

        self.active_timers[ip] = timer

        timer.start()

    # =====================================================

    def temp_block_ip(
        self,
        ip,
        timeout=EngineConfig.DEFAULT_TEMP_BLOCK,
        attack=None,
        severity=None,
        source="Suricata"
    ):

        with self.lock:

            result = self.block_ip(
                ip,
                attack=attack,
                severity=severity,
                source=source,
                block_type="temporary",
                timeout=timeout
            )

            if not result["success"]:

                return result

            self._start_timer(ip, timeout)

            result["action"] = "temporary_block"

            result["timeout"] = timeout

            return result

    # =====================================================
    # Utility Functions
    # =====================================================

    def is_blocked(self, ip):

        return ip in self.active_blocks

    # =====================================================

    def reload_whitelist(self):

        return self.get_whitelist()

    # =====================================================

    def clear_history(self):

        with self.lock:

            self._pending_history = []

            self._save_history([])

    # =====================================================

    def shutdown(self):

        with self.lock:

            for timer in self.active_timers.values():

                timer.cancel()

            self.active_timers.clear()

        self.flush_history()

        self.backend.disconnect()

        self.logger.info("Response Engine stopped.")

    # =====================================================

    def startup(self):

        try:

            # Dry-run represents an operationally healthy response layer: the
            # policy/action/history path is exercised, but no live ACL changes
            # are sent to real hardware.  Reconcile local state safely.
            if EngineConfig.DRY_RUN:
                self._sync_from_switch()
                self.logger.info("Response Engine started in DRY-RUN mode.")
                return True

            if EngineConfig.AUTO_CREATE_ACL:

                self.backend.ensure_acl()

            if EngineConfig.VERIFY_CONNECTION_ON_STARTUP:

                self.backend.connect()

            self._sync_from_switch()

            self.logger.info("Response Engine started.")

            return True

        except Exception as ex:

            self.logger.exception(ex)

            self.stats.total_errors += 1

            return False


if __name__ == "__main__":

    engine = ResponseEngine()

    if not engine.startup():

        print("Startup failed.")

        exit()

    print("\n========== Sentinel-AI Response Engine ==========\n")

    print("Current blocked IPs:")

    print(engine.get_active_blocks())

    print("\nBlocking 192.168.10.55 ...")

    result = engine.block_ip(

        ip="192.168.10.55",

        attack="Manual Test",

        severity="High",

        source="Console"

    )

    print(result)

    print("\nStatistics:")

    print(engine.get_stats())

    print("\nHistory:")

    print(engine.get_history())

    engine.shutdown()
