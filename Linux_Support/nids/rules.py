"""Deterministic fallbacks over Suricata alerts and reproducible flow signals."""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from collectors.suricata_parser import SuricataFlow

from .types import Detection


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    attack_type: str
    severity: str


class DeterministicRuleEngine:
    """Fallback detector.

    Suricata has already performed payload/rule inspection before an ``alert``
    reaches this component.  The engine translates a validated alert signature
    into a stable event schema, and also tracks simple flow-only scan/brute
    force indicators when ML is absent.
    """

    ALERT_RULES = (
        _Rule("SURICATA-ICMP-RECON", re.compile(r"\bicmp\b|ping", re.I), "ICMP Reconnaissance", "Medium"),
        _Rule("SURICATA-TCP-SCAN", re.compile(r"nmap|port\s*scan|syn\s*scan", re.I), "TCP SYN / Port Scan", "High"),
        _Rule("SURICATA-SSH-BRUTE", re.compile(r"\bssh.*(brute|login|auth|burst|scan)|brute.*ssh", re.I), "SSH Brute Force", "High"),
        _Rule("SURICATA-SQLI", re.compile(r"sql.?injection|sqli", re.I), "SQL Injection", "High"),
        _Rule("SURICATA-XSS", re.compile(r"cross.?site|\bxss\b", re.I), "Cross-Site Scripting", "High"),
        _Rule("SURICATA-LFI", re.compile(r"local.?file|\blfi\b|directory.?traversal", re.I), "Local File Inclusion", "High"),
        _Rule("SURICATA-DNS", re.compile(r"dns.*(anomal|tunnel|flood)|domain.*anomal", re.I), "DNS Anomaly", "Medium"),
        _Rule("SURICATA-DOS", re.compile(r"\bddos\b|\bdos\b|denial.of.service|syn\s*flood", re.I), "Denial of Service", "Critical"),
        _Rule("SURICATA-HTTP", re.compile(r"http.*attack|web.?attack", re.I), "HTTP Attack", "High"),
    )

    def __init__(self, window_seconds: int = 60, scan_port_threshold: int = 12, ssh_threshold: int = 6):
        self.window_seconds = window_seconds
        self.scan_port_threshold = scan_port_threshold
        self.ssh_threshold = ssh_threshold
        self._ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._ssh_attempts: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, values: deque, now: float) -> None:
        """Remove observations outside the bounded sliding window."""
        while values:
            timestamp = values[0][0] if isinstance(values[0], tuple) else values[0]
            if timestamp >= now - self.window_seconds:
                return
            values.popleft()

    def _trim_ip_dict(self, d: dict, ip: str, now: float) -> deque:
        """Trim the deque for *ip*, then drop the key if it is now empty."""
        q = d[ip]
        self._trim(q, now)
        if not q:
            d.pop(ip, None)
            return deque()
        return q

    def evaluate(self, flow: SuricataFlow) -> Optional[Detection]:
        signature = flow.alert_signature
        if signature:
            for rule in self.ALERT_RULES:
                if rule.pattern.search(signature):
                    return Detection(rule.attack_type, rule.severity, 1.0, "suricata", "rule", signature, rule.rule_id)
            return Detection("Suricata Security Alert", "High", 1.0, "suricata", "rule", signature, "SURICATA-ALERT")

        now = time.monotonic()

        # Port-scan tracking
        ports = self._ports[flow.src_ip]
        ports.append((now, flow.dest_port))
        ports = self._trim_ip_dict(self._ports, flow.src_ip, now)
        if flow.proto.lower() == "tcp" and len({port for _, port in ports}) >= self.scan_port_threshold:
            return Detection("TCP SYN / Port Scan", "High", 0.85, "deterministic", "fallback", rule_id="FLOW-PORT-SCAN")

        # SSH brute-force tracking
        if flow.app_proto == "ssh" or flow.dest_port == 22:
            attempts = self._ssh_attempts[flow.src_ip]
            attempts.append(now)
            attempts = self._trim_ip_dict(self._ssh_attempts, flow.src_ip, now)
            if len(attempts) >= self.ssh_threshold:
                return Detection("SSH Brute Force", "High", 0.80, "deterministic", "fallback", rule_id="FLOW-SSH-RATE")
        return None
