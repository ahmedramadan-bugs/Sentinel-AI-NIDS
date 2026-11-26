"""Professional local diagnostic and operational dashboard."""

from __future__ import annotations

import json
import mimetypes
import os
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from collectors.feature_alignment import FEATURE_COLUMNS
from collectors.suricata_parser import SuricataFlow
from .kali_console import KaliConsoleManager, PLAYBOOKS
from .topology import build_topology

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
STATIC_DIR = ROOT / "runtime" / "static"
METRICS_FILE = ROOT / "AI" / "models" / "xgboost_nids_artifacts" / "metrics.json"


def make_handler(pipeline: Any):
    kali_console = KaliConsoleManager(pipeline)

    class DashboardHandler(BaseHTTPRequestHandler):
        def _json(self, body: dict[str, Any], status: int = HTTPStatus.OK) -> None:
            encoded = json.dumps(body, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _serve_file(self, file_path: Path, allowed_root: Path, content_type: str | None = None) -> None:
            try:
                resolved_file = file_path.resolve()
                resolved_root = allowed_root.resolve()
                if not resolved_file.is_relative_to(resolved_root) or not resolved_file.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            ctype = content_type or mimetypes.guess_type(str(resolved_file))[0] or "application/octet-stream"
            with open(resolved_file, "rb") as f:
                data = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json_body(self) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                return {}
            raw = self.rfile.read(content_length).decode("utf-8")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}

        do_HEAD = lambda self: self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query = parse_qs(parsed_url.query)

            # Static vendor assets (Bootstrap, Chart.js, etc.)
            if path.startswith("/static/"):
                file_name = path.replace("/static/", "").strip("/")
                self._serve_file(STATIC_DIR / file_name, allowed_root=STATIC_DIR)
                return

            # Modular CSS files
            if path.startswith("/css/"):
                file_name = path.replace("/css/", "").strip("/")
                self._serve_file(WEB_DIR / "css" / file_name, allowed_root=WEB_DIR / "css", content_type="text/css; charset=utf-8")
                return

            # Modular JS files
            if path.startswith("/js/"):
                file_name = path.replace("/js/", "").strip("/")
                self._serve_file(WEB_DIR / "js" / file_name, allowed_root=WEB_DIR / "js", content_type="application/javascript; charset=utf-8")
                return

            # Standalone index.html
            if path == "/" or path == "/index.html":
                self._serve_file(WEB_DIR / "index.html", allowed_root=WEB_DIR, content_type="text/html; charset=utf-8")
                return

            # REST APIs
            if path == "/api/status":
                self._json(pipeline.status())
                return

            if path == "/api/events":
                limit = int(query.get("limit", ["100"])[0])
                self._json({"events": pipeline.store.recent(limit)})
                return

            if path.startswith("/api/events/"):
                event_id_str = path.split("/")[-1]
                if event_id_str.isdigit():
                    event = pipeline.store.get_event(int(event_id_str))
                    if event:
                        self._json(event)
                        return
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            if path == "/api/stats/traffic":
                range_key = query.get("range", ["24h"])[0]
                self._json(pipeline.store.traffic_series(range_key))
                return

            if path == "/api/stats/distribution":
                self._json(pipeline.store.attack_distribution())
                return

            if path == "/api/stats/analytics":
                self._json({
                    "top_attackers": pipeline.store.top_attackers(10),
                    "protocol_distribution": pipeline.store.protocol_distribution(),
                    "heatmap": pipeline.store.heatmap_data(),
                })
                return

            if path == "/api/models/metrics":
                metrics_data: dict[str, Any] = {}
                if METRICS_FILE.is_file():
                    with open(METRICS_FILE, "r", encoding="utf-8") as f:
                        metrics_data = json.load(f)
                model = getattr(pipeline.model, "model", None)
                if model and hasattr(model, "feature_importances_"):
                    importances = [float(x) for x in model.feature_importances_]
                    pairs = sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
                    metrics_data["feature_importances"] = [{"feature": f, "importance": imp} for f, imp in pairs]
                self._json(metrics_data)
                return

            if path == "/api/response/state":
                engine = getattr(pipeline.responder, "engine", None)
                if engine:
                    self._json({
                        "active_blocks": engine.get_active_blocks(),
                        "whitelist": engine.get_whitelist(),
                        "history": engine.get_history(),
                        "stats": engine.get_stats(),
                    })
                else:
                    self._json({
                        "active_blocks": [],
                        "whitelist": [],
                        "history": [],
                        "stats": {},
                    })
                return

            if path == "/api/settings":
                pol_eng = getattr(pipeline.responder, "policy_engine", None)
                policy_data = pol_eng.policy if pol_eng else {}
                cisco_host = os.getenv("NIDS_CISCO_HOST", "")
                cisco_user = os.getenv("NIDS_CISCO_USERNAME", "")
                self._json({
                    "policy": policy_data,
                    "cisco": {
                        "host": cisco_host,
                        "username": cisco_user,
                        "configured": bool(cisco_host and cisco_user),
                    },
                    "enforcement_mode": pol_eng.get_enforcement_mode() if pol_eng else "auto",
                    "temp_block_seconds": pol_eng.get_temp_block_seconds() if pol_eng else 300,
                })
                return

            if path == "/api/topology":
                self._json(build_topology(pipeline))
                return

            if path == "/api/kali/status":
                self._json(kali_console.status())
                return

            if path == "/api/kali/playbooks":
                self._json({"playbooks": PLAYBOOKS})
                return

            self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            data = self._read_json_body()
            engine = getattr(pipeline.responder, "engine", None)

            if path == "/api/response/block":
                ip = data.get("ip")
                attack = data.get("attack", "Manual Dashboard Block")
                severity = data.get("severity", "High")
                timeout_val = data.get("timeout")
                if timeout_val is None:
                    timeout_val = pipeline.settings.temp_block_seconds
                else:
                    try:
                        timeout_val = int(timeout_val)
                    except (ValueError, TypeError):
                        timeout_val = 300

                if not ip or not engine:
                    self._json({"success": False, "message": "Missing IP or ResponseEngine unavailable"}, status=HTTPStatus.BAD_REQUEST)
                    return

                if timeout_val == 0:
                    result = engine.block_ip(ip, attack=attack, severity=severity, source="Dashboard", block_type="permanent")
                else:
                    result = engine.temp_block_ip(ip, timeout=timeout_val, attack=attack, severity=severity, source="Dashboard")
                self._json(result)
                return

            if path == "/api/response/unblock":
                ip = data.get("ip")
                if not ip or not engine:
                    self._json({"success": False, "message": "Missing IP or ResponseEngine unavailable"}, status=HTTPStatus.BAD_REQUEST)
                    return
                result = engine.unblock_ip(ip, source="Dashboard")
                self._json(result)
                return

            if path == "/api/response/whitelist/add":
                ip = data.get("ip")
                if not ip or not engine:
                    self._json({"success": False, "message": "Missing IP or ResponseEngine unavailable"}, status=HTTPStatus.BAD_REQUEST)
                    return
                ok = engine.add_to_whitelist(ip, source="Dashboard")
                self._json({"success": ok, "ip": ip})
                return

            if path == "/api/response/whitelist/remove":
                ip = data.get("ip")
                if not ip or not engine:
                    self._json({"success": False, "message": "Missing IP or ResponseEngine unavailable"}, status=HTTPStatus.BAD_REQUEST)
                    return
                ok = engine.remove_from_whitelist(ip)
                self._json({"success": ok, "ip": ip})
                return

            if path == "/api/settings":
                pol_eng = getattr(pipeline.responder, "policy_engine", None)
                if not pol_eng:
                    self._json({"success": False, "message": "Policy engine unavailable"}, status=HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                updated = pol_eng.update_policy(data)
                self._json({"success": True, "policy": updated})
                return

            if path == "/api/test-cisco":
                host = data.get("host") or os.getenv("NIDS_CISCO_HOST", "")
                if not host:
                    self._json({"success": False, "message": "Cisco Host IP required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                try:
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.5)
                    res = sock.connect_ex((host, 22))
                    sock.close()
                    if res == 0:
                        self._json({"success": True, "message": f"Successfully connected to SSH port 22 on {host}"})
                    else:
                        self._json({"success": False, "message": f"Connection refused or timed out on {host}:22"})
                except Exception as ex:
                    self._json({"success": False, "message": f"Connection error: {ex}"})
                return

            if path == "/api/kali/connect":
                self._json(kali_console.connect(data))
                return

            if path == "/api/kali/disconnect":
                self._json(kali_console.disconnect())
                return

            if path == "/api/kali/exec":
                command = str(data.get("command") or "")
                target = str(data.get("target") or "192.168.56.10")
                self._json(kali_console.execute(command, target=target))
                return

            self.send_error(HTTPStatus.NOT_FOUND)

        def log_message(self, *_: Any) -> None:
            return

    return DashboardHandler


def create_server(pipeline: Any) -> ThreadingHTTPServer:
    settings = pipeline.settings
    return ThreadingHTTPServer((settings.dashboard_host, settings.dashboard_port), make_handler(pipeline))
