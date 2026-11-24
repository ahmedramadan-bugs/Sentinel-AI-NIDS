"""
Suricata Log Parser for AI-NIDS
Parses Suricata EVE JSON logs and alert logs
"""

import json
import os
import time
from typing import Dict, List, Optional, Generator, Callable
from datetime import datetime, timezone
from dataclasses import dataclass
import threading
import logging
import re

logger = logging.getLogger(__name__)


def _parse_suricata_ts(ts: str) -> datetime:
    """
    Parse Suricata EVE timestamps like '2026-07-22T19:45:52.348936+0300'.
    datetime.fromisoformat() rejects timezone offsets without a colon
    (e.g. '+0300' instead of '+03:00') on Python < 3.11, so use
    strptime instead, which handles both forms.
    """
    ts = ts.strip().replace('Z', '+0000')
    try:
        return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
    except ValueError:
        try:
            # some events have no microseconds
            return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S%z')
        except ValueError:
            # Test fixtures and a few log shippers omit the timezone.  Treat
            # them as UTC rather than failing the whole event stream.
            parsed = datetime.fromisoformat(ts)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)


@dataclass
class SuricataFlow:
    """Represents a parsed Suricata flow."""
    timestamp: datetime
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    app_proto: Optional[str] = None
    
    # Flow statistics
    bytes_toserver: int = 0
    bytes_toclient: int = 0
    pkts_toserver: int = 0
    pkts_toclient: int = 0
    
    # Duration
    flow_start: Optional[datetime] = None
    flow_end: Optional[datetime] = None
    
    # Suricata alert info (if any)
    alert_signature: Optional[str] = None
    alert_category: Optional[str] = None
    alert_severity: Optional[int] = None
    
    # Raw event
    raw_event: Optional[Dict] = None
    
    def to_features(self) -> Dict:
        """Convert to feature dictionary for ML model."""
        duration = 0
        if self.flow_start and self.flow_end:
            duration = (self.flow_end - self.flow_start).total_seconds() * 1000000  # microseconds
        
        total_bytes = self.bytes_toserver + self.bytes_toclient
        total_pkts = self.pkts_toserver + self.pkts_toclient
        
        return {
            'Source IP': self.src_ip,
            'Destination IP': self.dest_ip,
            'Source Port': self.src_port,
            'Destination Port': self.dest_port,
            'Protocol': self._proto_to_int(),
            'Flow Duration': duration,
            'Total Fwd Packets': self.pkts_toserver,
            'Total Backward Packets': self.pkts_toclient,
            'Total Length of Fwd Packets': self.bytes_toserver,
            'Total Length of Bwd Packets': self.bytes_toclient,
            'Flow Bytes/s': total_bytes / max(duration / 1000000, 0.001),
            'Flow Packets/s': total_pkts / max(duration / 1000000, 0.001),
            'Fwd Packets/s': self.pkts_toserver / max(duration / 1000000, 0.001),
            'Bwd Packets/s': self.pkts_toclient / max(duration / 1000000, 0.001),
            'Down/Up Ratio': self.bytes_toclient / max(self.bytes_toserver, 1),
            'Average Packet Size': total_bytes / max(total_pkts, 1)
        }
    
    def _proto_to_int(self) -> int:
        """Convert protocol string to integer."""
        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'sctp': 132}
        return proto_map.get(self.proto.lower(), 0)


class SuricataParser:
    """
    Parser for Suricata log files.
    Supports EVE JSON format and traditional alert format.
    """
    
    def __init__(
        self,
        eve_log_path: Optional[str] = None,
        alert_log_path: Optional[str] = None,
        config: Optional[Dict] = None
    ):
        """
        Initialize Suricata parser.
        
        Args:
            eve_log_path: Path to EVE JSON log file
            alert_log_path: Path to traditional alert log
            config: Configuration dictionary
        """
        self.eve_log_path = eve_log_path or '/var/log/suricata/eve.json'
        self.alert_log_path = alert_log_path or '/var/log/suricata/fast.log'
        self.config = config or {}
        
        # Parsing state
        self._last_position: Dict[str, int] = {}
        self._running = False
        self._watch_thread: Optional[threading.Thread] = None
        
        # Event handlers
        self.flow_handlers: List[Callable] = []
        self.alert_handlers: List[Callable] = []
        
        logger.info(f"SuricataParser initialized with EVE log: {self.eve_log_path}")
    
    def parse_eve_event(self, line: str) -> Optional[SuricataFlow]:
        """
        Parse a single EVE JSON event.
        
        Args:
            line: JSON line from EVE log
            
        Returns:
            SuricataFlow or None
        """
        try:
            event = json.loads(line.strip())
            
            event_type = event.get('event_type')
            
            if event_type == 'flow':
                return self._parse_flow_event(event)
            elif event_type == 'alert':
                return self._parse_alert_event(event)
            elif event_type in ['http', 'dns', 'tls', 'ssh', 'smtp']:
                return self._parse_protocol_event(event)
            
            return None
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse EVE event: {e}")
            return None
    
    def _parse_flow_event(self, event: Dict) -> SuricataFlow:
        """Parse flow event."""
        flow_data = event.get('flow', {})
        
        start_str = flow_data.get('start')
        end_str = flow_data.get('end')
        
        return SuricataFlow(
            timestamp=_parse_suricata_ts(event['timestamp']),
            src_ip=event.get('src_ip', ''),
            src_port=event.get('src_port', 0),
            dest_ip=event.get('dest_ip', ''),
            dest_port=event.get('dest_port', 0),
            proto=event.get('proto', 'tcp'),
            app_proto=event.get('app_proto'),
            bytes_toserver=flow_data.get('bytes_toserver', 0),
            bytes_toclient=flow_data.get('bytes_toclient', 0),
            pkts_toserver=flow_data.get('pkts_toserver', 0),
            pkts_toclient=flow_data.get('pkts_toclient', 0),
            flow_start=_parse_suricata_ts(start_str) if start_str else None,
            flow_end=_parse_suricata_ts(end_str) if end_str else None,
            raw_event=event
        )
    
    def _parse_alert_event(self, event: Dict) -> SuricataFlow:
        """Parse alert event."""
        alert_data = event.get('alert', {})
        flow_data = event.get('flow', {})
        
        start_str = flow_data.get('start')
        end_str = flow_data.get('end')
        
        return SuricataFlow(
            timestamp=_parse_suricata_ts(event['timestamp']),
            src_ip=event.get('src_ip', ''),
            src_port=event.get('src_port', 0),
            dest_ip=event.get('dest_ip', ''),
            dest_port=event.get('dest_port', 0),
            proto=event.get('proto', 'tcp'),
            app_proto=event.get('app_proto'),
            bytes_toserver=flow_data.get('bytes_toserver', 0),
            bytes_toclient=flow_data.get('bytes_toclient', 0),
            pkts_toserver=flow_data.get('pkts_toserver', 0),
            pkts_toclient=flow_data.get('pkts_toclient', 0),
            flow_start=_parse_suricata_ts(start_str) if start_str else None,
            flow_end=_parse_suricata_ts(end_str) if end_str else None,
            alert_signature=alert_data.get('signature'),
            alert_category=alert_data.get('category'),
            alert_severity=alert_data.get('severity'),
            raw_event=event
        )
    
    def _parse_protocol_event(self, event: Dict) -> SuricataFlow:
        """Parse protocol-specific event (HTTP, DNS, etc.)."""
        return SuricataFlow(
            timestamp=_parse_suricata_ts(event['timestamp']),
            src_ip=event.get('src_ip', ''),
            src_port=event.get('src_port', 0),
            dest_ip=event.get('dest_ip', ''),
            dest_port=event.get('dest_port', 0),
            proto=event.get('proto', 'tcp'),
            app_proto=event.get('event_type'),
            raw_event=event
        )
    
    def parse_eve_file(
        self,
        file_path: Optional[str] = None,
        from_position: int = 0
    ) -> Generator[SuricataFlow, None, None]:
        """
        Parse EVE JSON log file.
        
        Args:
            file_path: Path to EVE log file
            from_position: Start position in file
            
        Yields:
            SuricataFlow objects
        """
        path = file_path or self.eve_log_path
        
        if not os.path.exists(path):
            logger.warning(f"EVE log not found: {path}")
            return
        
        # Handle normal log rotation/truncation: an old byte offset is invalid
        # once Suricata creates a fresh eve.json, so resume at its beginning.
        start = min(max(0, from_position), os.path.getsize(path))
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(start)
            
            for line in f:
                flow = self.parse_eve_event(line)
                if flow:
                    yield flow
            
            self._last_position[path] = f.tell()
    
    def parse_alert_line(self, line: str) -> Optional[Dict]:
        """
        Parse Suricata fast.log alert line.
        
        Format: MM/DD/YYYY-HH:MM:SS.ssssss [**] [gid:sid:rev] signature [**] [Classification: class] [Priority: N] {proto} src:port -> dst:port
        """
        pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)'
        
        match = re.match(pattern, line.strip())
        if match:
            return {
                'timestamp': match.group(1),
                'sid': match.group(2),
                'signature': match.group(3),
                'classification': match.group(4),
                'priority': int(match.group(5)),
                'proto': match.group(6),
                'src_ip': match.group(7),
                'src_port': int(match.group(8)),
                'dest_ip': match.group(9),
                'dest_port': int(match.group(10))
            }
        
        return None
    
    def parse_alert_file(
        self,
        file_path: Optional[str] = None
    ) -> Generator[Dict, None, None]:
        """
        Parse Suricata fast.log file.
        
        Args:
            file_path: Path to alert log file
            
        Yields:
            Alert dictionaries
        """
        path = file_path or self.alert_log_path
        
        if not os.path.exists(path):
            logger.warning(f"Alert log not found: {path}")
            return
        
        with open(path, 'r') as f:
            for line in f:
                alert = self.parse_alert_line(line)
                if alert:
                    yield alert
    
    def register_flow_handler(self, handler: Callable) -> None:
        """Register a flow event handler."""
        self.flow_handlers.append(handler)
    
    def register_alert_handler(self, handler: Callable) -> None:
        """Register an alert event handler."""
        self.alert_handlers.append(handler)
    
    def start_watching(self, poll_interval: float = 0.1) -> None:
        """
        Start watching log files for new entries.
        
        Args:
            poll_interval: Seconds between polls
        """
        if self._running:
            return

        path = self.eve_log_path
        if os.path.exists(path) and path not in self._last_position:
            self._last_position[path] = os.path.getsize(path)

        self._running = True
        self._watch_thread = threading.Thread(
            target=self._watch_logs,
            args=(poll_interval,),
            daemon=True
        )
        self._watch_thread.start()
        logger.info("Started watching Suricata logs (high-performance follower mode)")

    def stop_watching(self) -> None:
        """Stop watching log files."""
        self._running = False
        if self._watch_thread:
            self._watch_thread.join(timeout=5)
        logger.info("Stopped watching Suricata logs")

    def _watch_logs(self, poll_interval: float = 0.1) -> None:
        """Continuously tail EVE log file with rotation and truncation handling."""
        path = self.eve_log_path
        current_file = None
        current_inode = None
        _last_heartbeat = time.monotonic()
        _HEARTBEAT_INTERVAL = 60  # seconds
        _total_lines_parsed = 0
        _total_parse_failures = 0

        while self._running:
            try:
                # ── Heartbeat ──────────────────────────────────────────
                now_mono = time.monotonic()
                if now_mono - _last_heartbeat >= _HEARTBEAT_INTERVAL:
                    logger.info(
                        "[NIDS heartbeat] watcher alive | path=%s | "
                        "lines_parsed=%d | parse_failures=%d",
                        path, _total_lines_parsed, _total_parse_failures,
                    )
                    _last_heartbeat = now_mono

                if not os.path.exists(path):
                    time.sleep(0.5)
                    continue

                stat = os.stat(path)
                # Check for file rotation or initial open
                if current_file is None or stat.st_ino != current_inode:
                    if current_file:
                        logger.info(
                            "[NIDS reopen] EVE log rotated or replaced | "
                            "old_inode=%s new_inode=%s path=%s",
                            current_inode, stat.st_ino, path,
                        )
                        try:
                            current_file.close()
                        except Exception:
                            pass
                    else:
                        logger.info("[NIDS open] EVE log opened | path=%s", path)
                    current_file = open(path, "r", encoding="utf-8", errors="replace")
                    current_inode = stat.st_ino
                    start_pos = self._last_position.get(path, stat.st_size)
                    if start_pos > stat.st_size:
                        start_pos = 0
                    current_file.seek(start_pos)
                elif stat.st_size < current_file.tell():
                    # File was truncated
                    logger.warning(
                        "[NIDS truncation] EVE log truncated | "
                        "old_offset=%d new_size=%d path=%s",
                        current_file.tell(), stat.st_size, path,
                    )
                    current_file.seek(0)

                # Read all available lines
                lines_read = 0
                while self._running:
                    line = current_file.readline()
                    if not line:
                        break
                    # If line is incomplete (e.g. at EOF without newline), seek back to start of line
                    if not line.endswith("\n") and current_file.tell() >= stat.st_size:
                        current_file.seek(current_file.tell() - len(line.encode("utf-8", errors="replace")))
                        break

                    lines_read += 1
                    _total_lines_parsed += 1
                    flow = self.parse_eve_event(line)
                    if flow:
                        if flow.alert_signature:
                            for handler in self.alert_handlers:
                                try:
                                    handler(flow)
                                except Exception as e:
                                    logger.error(f"Alert handler error: {e}")
                        else:
                            for handler in self.flow_handlers:
                                try:
                                    handler(flow)
                                except Exception as e:
                                    logger.error(f"Flow handler error: {e}")
                    else:
                        # Log first 120 chars of unparseable lines at DEBUG level
                        _total_parse_failures += 1
                        logger.debug(
                            "[NIDS parse-fail] could not parse EVE line | preview=%r",
                            line[:120],
                        )

                self._last_position[path] = current_file.tell()
                time.sleep(0.05 if lines_read else 0.15)

            except Exception as e:
                logger.error(f"Log watch error: {e}")
                time.sleep(0.5)

        if current_file:
            try:
                current_file.close()
            except Exception:
                pass


def create_suricata_parser(
    eve_log_path: Optional[str] = None,
    config: Optional[Dict] = None
) -> SuricataParser:
    """Factory function to create SuricataParser."""
    return SuricataParser(eve_log_path=eve_log_path, config=config)
