"""Live network topology builder from NIDS events and response state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _is_internal(ip: str) -> bool:
    return (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("127.")
        or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31 if len(ip.split(".")) >= 2 and ip.split(".")[1].isdigit() else False)
    )


def build_topology(pipeline: Any, limit: int = 250) -> dict[str, Any]:
    """Aggregate recent events into nodes and edges for the Topology map."""
    events = pipeline.store.recent(limit)
    now = datetime.now(timezone.utc)
    online_cutoff = now - timedelta(minutes=15)
    attack_cutoff = now - timedelta(minutes=10)

    blocked_ips: set[str] = set()
    engine = getattr(pipeline.responder, "engine", None)
    if engine:
        for item in engine.get_active_blocks():
            if item.get("ip"):
                blocked_ips.add(str(item["ip"]))

    nodes_map: dict[str, dict[str, Any]] = {}
    edges_map: dict[tuple[str, str], dict[str, Any]] = {}

    def ensure_node(ip: str, role_hint: str = "host") -> dict[str, Any]:
        if ip not in nodes_map:
            nodes_map[ip] = {
                "id": ip,
                "ip": ip,
                "label": ip,
                "role": role_hint if _is_internal(ip) else "external",
                "internal": _is_internal(ip),
                "status": "offline",
                "alert_count": 0,
                "last_attack": None,
                "last_severity": "Info",
                "last_seen": None,
                "_last_seen_dt": None,
                "_attacking": False,
            }
        return nodes_map[ip]

    for ev in events:
        src = str(ev.get("src_ip") or "").strip()
        dst = str(ev.get("dest_ip") or "").strip()
        if not src or not dst:
            continue

        ts = _parse_ts(ev.get("timestamp"))
        attack = str(ev.get("attack_type") or "Normal")
        severity = str(ev.get("severity") or "Info")
        is_attack = attack.lower() not in {"normal", "benign", ""}

        src_node = ensure_node(src)
        dst_node = ensure_node(dst)

        for node in (src_node, dst_node):
            if ts and (node["_last_seen_dt"] is None or ts > node["_last_seen_dt"]):
                node["_last_seen_dt"] = ts
                node["last_seen"] = ts.isoformat()

        if is_attack:
            src_node["alert_count"] += 1
            if src_node["last_attack"] is None:
                src_node["last_attack"] = attack
                src_node["last_severity"] = severity
            if ts is None or ts >= attack_cutoff:
                src_node["_attacking"] = True

        edge_key = (src, dst)
        if edge_key not in edges_map:
            edges_map[edge_key] = {
                "source": src,
                "target": dst,
                "count": 0,
                "attack_type": attack if is_attack else "Normal",
                "severity": severity,
                "active_attack": is_attack and (ts is None or ts >= attack_cutoff),
            }
        edges_map[edge_key]["count"] += 1
        if is_attack and edges_map[edge_key]["attack_type"] == "Normal":
            edges_map[edge_key]["attack_type"] = attack
            edges_map[edge_key]["severity"] = severity
            if ts is None or ts >= attack_cutoff:
                edges_map[edge_key]["active_attack"] = True

    nodes: list[dict[str, Any]] = []
    stats = {"total": 0, "online": 0, "offline": 0, "attacking": 0, "blocked": 0}

    for node in nodes_map.values():
        last_dt = node.pop("_last_seen_dt")
        attacking = node.pop("_attacking")
        if node["ip"] in blocked_ips:
            node["status"] = "blocked"
            node["role"] = "attacker"
            stats["blocked"] += 1
        elif attacking:
            node["status"] = "attacking"
            node["role"] = "attacker"
            stats["attacking"] += 1
        elif last_dt and last_dt >= online_cutoff:
            node["status"] = "online"
            stats["online"] += 1
        else:
            node["status"] = "offline"
            stats["offline"] += 1
        stats["total"] += 1
        nodes.append(node)

    # Sort attackers first, then online, then offline
    order = {"attacking": 0, "blocked": 1, "online": 2, "offline": 3}
    nodes.sort(key=lambda n: (order.get(n["status"], 9), -n["alert_count"], n["ip"]))

    return {
        "nodes": nodes[:24],
        "edges": list(edges_map.values())[:40],
        "stats": stats,
        "generated_at": now.isoformat(),
    }
