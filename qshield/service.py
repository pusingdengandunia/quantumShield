"""Application flow: register targets, discover services, run scans, build the dashboard."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from . import config, db, gateway, risk
from .scanners import tls as tls_scanner
from .scanners.code import scan_code
from .scanners.ssh import scan_ssh
from .scanners.tls import scan_tls

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
HOST_HELP = "Contoh yang benar: mail.google.com atau 10.0.0.5."

# Fixed list on purpose: discovery checks these ports only and takes no port range.
DISCOVERY_PORTS = {443: "HTTPS", 8443: "HTTPS alternatif", 22: "SSH", 465: "SMTPS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S"}
_GATEWAY_PORTS = {443, 8443}
_DEFAULT_PORTS = {"tls": 443, "ssh": 22}

_progress = {"running": False, "done": 0, "total": 0, "current": None}


class TargetError(ValueError):
    pass


def normalize_host(value: str | None) -> tuple[str, int | None]:
    """Accept a pasted URL or host:port. The result still has to pass the strict host check."""
    value = (value or "").strip()
    if not value:
        raise TargetError(f"Host wajib diisi. {HOST_HELP}")
    try:
        parts = urlsplit(value if "://" in value else f"//{value}")
        host, port = parts.hostname or "", parts.port
    except ValueError as error:
        raise TargetError(f"Nama host tidak valid. {HOST_HELP}") from error
    if not _HOST_RE.match(host):
        raise TargetError(f"Nama host tidak valid. {HOST_HELP}")
    return host, port


def ensure_host_allowed(host: str) -> None:
    """Refuse public addresses unless the operator opted in. Every resolved address must pass."""
    if not _HOST_RE.match(host or ""):
        raise TargetError(f"Nama host tidak valid. {HOST_HELP}")
    if config.allow_public_targets():
        return
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError as error:
        raise TargetError(f"Host {host} tidak bisa di-resolve.") from error
    for address in addresses:
        parsed = ipaddress.ip_address(address.split("%")[0])
        if not (parsed.is_private or parsed.is_loopback):
            raise TargetError(f"{host} mengarah ke alamat publik {address}. Scan alamat publik dinonaktifkan.")


def _ensure_repo_allowed(path: str) -> str:
    root = config.repo_root()
    if root is None:
        raise TargetError("Scan kode dinonaktifkan: QSHIELD_REPO_ROOT belum diatur.")
    resolved = Path(path).resolve()
    if resolved != root and root not in resolved.parents:
        raise TargetError(f"Path harus berada di dalam {root}.")
    if not resolved.is_dir():
        raise TargetError("Folder tidak ditemukan.")
    return str(resolved)


def register_target(values: dict) -> int:
    values = {"host": None, "port": None, "path": None, "server": None, **values}
    if values["kind"] in {"tls", "ssh"}:
        host, url_port = normalize_host(values["host"])
        ensure_host_allowed(host)
        values["host"], values["port"] = host, url_port or values["port"] or _DEFAULT_PORTS[values["kind"]]
        if not values["port"] or not 0 < values["port"] < 65536:
            raise TargetError("Port tidak valid.")
        values["path"] = None
        values["server"] = values["server"] or host
    elif values["kind"] == "repo":
        values["path"] = _ensure_repo_allowed(values["path"] or "")
        values["host"] = values["port"] = None
        values["server"] = values["server"] or values["name"]
    else:
        raise TargetError("Jenis target tidak dikenal.")
    if values["kind"] == "ssh" and values["migration"] == "gateway":
        raise TargetError("Gateway hanya untuk layanan TLS/HTTPS.")
    try:
        return db.add_target(values)
    except Exception as error:
        if "UNIQUE" in str(error):
            raise TargetError("Nama target sudah dipakai.") from error
        raise


def seed_targets() -> None:
    seed = config.seed_file()
    if seed is None or db.list_targets():
        return
    for entry in json.loads(seed.read_text(encoding="utf-8")):
        register_target(entry)


def _detect_service(host: str, port: int) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.settimeout(1.5)
            try:
                banner = sock.recv(16)
            except OSError:
                banner = b""
    except OSError:
        return None
    if banner.startswith(b"SSH-"):
        kind = "ssh"
    elif tls_scanner.succeeded(tls_scanner.handshake(host, port, timeout=5)):
        kind = "tls"
    else:
        return None
    return {"port": port, "kind": kind, "label": DISCOVERY_PORTS[port]}


def discover_services(host_value: str) -> dict:
    """Check the fixed port list and name the TLS and SSH services that answer."""
    host, _ = normalize_host(host_value)
    ensure_host_allowed(host)
    with ThreadPoolExecutor(max_workers=len(DISCOVERY_PORTS)) as pool:
        found = list(pool.map(lambda port: _detect_service(host, port), DISCOVERY_PORTS))
    registered = {t["port"] for t in db.list_targets() if t["host"] == host}
    services = [{**service, "registered": service["port"] in registered} for service in found if service]
    return {"host": host, "checked": list(DISCOVERY_PORTS), "services": services}


def register_server(host_value: str, services: list[dict], sensitivity: str, exposure: str, migration: str) -> list[int]:
    host, _ = normalize_host(host_value)
    created = []
    for service in services:
        port, kind = service["port"], service["kind"]
        if port not in DISCOVERY_PORTS:
            raise TargetError(f"Port {port} tidak ada di daftar deteksi.")
        # The gateway only proxies HTTP(S), so mail, LDAP and SSH services cannot use it.
        fitted = migration if migration != "gateway" or (kind == "tls" and port in _GATEWAY_PORTS) else "update"
        created.append(register_target({"name": f"{host}:{port}", "kind": kind, "host": host, "port": port,
                                        "server": host, "sensitivity": sensitivity, "exposure": exposure,
                                        "migration": fitted}))
    return created


def _scan_network(target: dict) -> dict:
    """Refusal at scan time too: a name may have been re-pointed since registration."""
    try:
        ensure_host_allowed(target["host"])
    except TargetError as error:
        return {"reachable": False, "items": [], "findings": [{"severity": "warning", "text": str(error)}]}
    return scan_tls(target["host"], target["port"]) if target["kind"] == "tls" else scan_ssh(target["host"], target["port"])


def _scan_tls_with_gateway(target: dict) -> dict:
    direct = _scan_network(target)
    protected = scan_tls(config.gateway_host(), target["gateway_port"])
    if not protected.get("hybrid"):
        db.set_gateway(target["id"], target["gateway_port"], "gagal")
        direct["findings"].append({"severity": "warning", "text": "Gateway terpasang tetapi handshake hybrid gagal."})
        return direct
    db.set_gateway(target["id"], target["gateway_port"], "aktif")
    protected["findings"].append({"severity": "info", "text": "Koneksi gateway ke layanan asal masih klasik; "
                                                              "letakkan keduanya di segmen tepercaya."})
    if direct["reachable"] and not direct.get("hybrid"):
        protected["drivers"].append({"code": "direct_open"})
        protected["findings"].append({"severity": "warning", "text": f"Akses langsung {target['host']}:{target['port']} "
                                                                     "masih terbuka dan klasik; tutup lewat firewall."})
    protected["direct"] = {"reachable": direct["reachable"], "cipher": direct.get("cipher"),
                           "versions": direct.get("versions")}
    return protected


def scan_target(target: dict) -> dict:
    if target["kind"] == "repo":
        return scan_code(target["path"])
    if target["kind"] == "tls" and target["gateway_port"]:
        return _scan_tls_with_gateway(target)
    return _scan_network(target)


def scan_progress() -> dict:
    return dict(_progress)


def run_scan() -> int:
    settings = db.get_settings()
    targets = db.list_targets()
    results = []
    _progress.update(running=True, done=0, total=len(targets), current=None)
    try:
        for target in targets:
            _progress["current"] = target["name"]
            scanned = scan_target(target)
            items = scanned.pop("items")
            findings = scanned.pop("findings")
            reachable = scanned.pop("reachable")
            drivers = scanned.pop("drivers", [])
            results.append({
                "target_id": target["id"],
                "target_name": target["name"],
                "reachable": reachable,
                "items": items,
                "findings": findings,
                "detail": scanned,
                "assessment": risk.assess(items, target["sensitivity"], target["exposure"], target["migration"],
                                          settings, drivers=drivers),
            })
            _progress["done"] += 1
    finally:
        _progress.update(running=False, current=None)
    return db.save_scan(results, risk.readiness(results))


def apply_gateway(target_id: int) -> dict:
    target = db.get_target(target_id)
    if target is None:
        raise TargetError("Target tidak ditemukan.")
    if target["kind"] != "tls" or target["migration"] != "gateway":
        raise TargetError("Aset ini tidak bisa memakai gateway; masuk roadmap migrasi.")
    ensure_host_allowed(target["host"])
    used = {t["gateway_port"] for t in db.list_targets() if t["gateway_port"]}
    port = gateway.apply_route(target, used)
    db.set_gateway(target_id, port, "menunggu")
    active = gateway.wait_for_hybrid(port)
    status = "aktif" if active else "gagal"
    db.set_gateway(target_id, port, status)
    return {"port": port, "status": status}


def remove_gateway(target_id: int) -> None:
    gateway.remove_route(target_id)
    db.set_gateway(target_id, None, None)


def run_benchmark(target_id: int) -> dict:
    target = db.get_target(target_id)
    if target is None or not target["gateway_port"]:
        raise TargetError("Terapkan gateway dulu sebelum benchmark.")
    result = gateway.benchmark(config.gateway_host(), target["gateway_port"])
    db.save_benchmark(target_id, result)
    return result


def executive_summary(readiness: float | None, rows: list[dict]) -> str:
    """Deterministic briefing text for the commander; no external model is involved."""
    if readiness is None:
        return "Belum ada hasil scan."
    reachable = [row for row in rows if row["reachable"]]
    urgent = sum(1 for row in reachable if row["priority"] == "P1")
    vulnerable = sum(1 for row in reachable if row["assessment"]["mosca_vulnerable"])
    protected = sum(1 for row in reachable if row["status"] in {"protected", "partial"})
    text = (f"Dari {len(reachable)} aset terpindai, {urgent} berprioritas P1, {vulnerable} rentan menurut teorema Mosca, "
            f"dan {protected} sudah terlindungi penuh atau sebagian.")
    first = next((row for row in rows if row["reachable"] and row["assessment"]["risk"] > 0), None)
    if first:
        text += f" Prioritas pertama: {first['target_name']} (risiko {first['assessment']['risk']:.1f})."
    return text


def _server_groups(rows: list[dict]) -> list[dict]:
    """A server is as weak as its weakest service, so it takes the highest risk."""
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["target"].get("server") or row["target_name"], []).append(row)
    return [{"server": server, "services": len(members), "risk": max(m["assessment"]["risk"] for m in members),
             "priority": members[0]["priority"], "target_ids": [m["target_id"] for m in members]}
            for server, members in groups.items()]


def dashboard() -> dict:
    targets = db.list_targets()
    by_id = {target["id"]: target for target in targets}
    benchmarks = db.list_benchmarks()
    rows = []
    for result in db.latest_results():
        target = by_id.get(result["target_id"])
        if target is None:
            continue
        status = risk.classify(result)
        rows.append({**result, "target": target, "benchmark": benchmarks.get(target["id"]), "status": status,
                     "status_label": risk.STATUS_LABELS[status], "priority": risk.PRIORITY_BY_STATUS[status]})
    rows.sort(key=risk.sort_key)
    history = db.scan_history()
    current = history[-1]["readiness"] if history else None
    previous = history[-2]["readiness"] if len(history) > 1 else None
    reachable = [row for row in rows if row["reachable"]]
    roadmap = [entry for entry in map(risk.roadmap_entry, rows) if entry]
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in risk.STATUS_LABELS}
    return {
        "read_only": config.read_only(),
        "readiness": current,
        "previous_readiness": previous,
        "history": history,
        "scanned_at": history[-1]["finished_at"] if history else None,
        "kpi": {
            "assets": len(rows),
            "reachable": len(reachable),
            "p1": sum(1 for row in rows if row["priority"] == "P1"),
            "mosca_vulnerable": sum(1 for row in reachable if row["assessment"]["mosca_vulnerable"]),
            "pqc_auth": sum(1 for row in reachable if (row["detail"].get("pki") or {}).get("auth_status") == "pqc"),
            "protected": counts["protected"],
            "critical_findings": sum(1 for row in rows for f in row["findings"] if f["severity"] == "critical"),
        },
        "status_counts": counts,
        "status_labels": risk.STATUS_LABELS,
        "rows": rows,
        "servers": _server_groups(rows),
        "targets": targets,
        "roadmap": roadmap,
        "summary": executive_summary(current, rows),
        "settings": db.get_settings(),
        "options": {
            "sensitivity": {key: value["label"] for key, value in risk.SENSITIVITY.items()},
            "exposure": {key: value["label"] for key, value in risk.EXPOSURE.items()},
            "migration": {key: value["label"] for key, value in risk.MIGRATION.items()},
        },
    }
