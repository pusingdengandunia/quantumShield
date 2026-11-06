"""Application flow: register targets, run scans, build the dashboard payload."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
from pathlib import Path

from . import config, db, gateway, risk
from .scanners.code import scan_code
from .scanners.ssh import scan_ssh
from .scanners.tls import scan_tls

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


class TargetError(ValueError):
    pass


def ensure_host_allowed(host: str) -> None:
    """Refuse public addresses unless the operator opted in. Every resolved address must pass."""
    if not _HOST_RE.match(host or ""):
        raise TargetError("Nama host tidak valid.")
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
    values = {"host": None, "port": None, "path": None, **values}
    if values["kind"] in {"tls", "ssh"}:
        ensure_host_allowed(values["host"])
        if not values["port"] or not 0 < values["port"] < 65536:
            raise TargetError("Port tidak valid.")
        values["path"] = None
    elif values["kind"] == "repo":
        values["path"] = _ensure_repo_allowed(values["path"] or "")
        values["host"] = values["port"] = None
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
    if direct["reachable"]:
        protected["findings"].append({"severity": "warning", "text": f"Akses langsung {target['host']}:{target['port']} "
                                                                     "masih terbuka; tutup lewat firewall."})
    protected["direct"] = {"reachable": direct["reachable"], "cipher": direct.get("cipher"),
                           "versions": direct.get("versions")}
    return protected


def scan_target(target: dict) -> dict:
    if target["kind"] == "repo":
        return scan_code(target["path"])
    if target["kind"] == "tls" and target["gateway_port"]:
        return _scan_tls_with_gateway(target)
    return _scan_network(target)


def run_scan() -> int:
    settings = db.get_settings()
    results = []
    for target in db.list_targets():
        scanned = scan_target(target)
        items = scanned.pop("items")
        findings = scanned.pop("findings")
        reachable = scanned.pop("reachable")
        results.append({
            "target_id": target["id"],
            "target_name": target["name"],
            "reachable": reachable,
            "items": items,
            "findings": findings,
            "detail": scanned,
            "assessment": risk.assess(items, target["sensitivity"], target["exposure"], target["migration"], settings),
        })
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
    vulnerable = [row for row in reachable if row["assessment"]["mosca_vulnerable"]]
    safe = [row for row in reachable if row["assessment"]["risk"] == 0]
    text = (f"Skor kesiapan kuantum satuan {readiness:.1f} dari 100. Dari {len(reachable)} aset terpindai, "
            f"{len(vulnerable)} rentan menurut teorema Mosca dan {len(safe)} sudah terlindungi.")
    worst = max(reachable, key=lambda row: row["assessment"]["risk"], default=None)
    if worst and worst["assessment"]["risk"] > 0:
        text += f" Prioritas pertama: {worst['target_name']} (risiko {worst['assessment']['risk']:.1f})."
    return text


def dashboard() -> dict:
    targets = db.list_targets()
    by_id = {target["id"]: target for target in targets}
    results = db.latest_results()
    benchmarks = db.list_benchmarks()
    rows = []
    for result in sorted(results, key=lambda r: r["assessment"]["risk"], reverse=True):
        target = by_id.get(result["target_id"])
        if target is None:
            continue
        rows.append({**result, "target": target, "benchmark": benchmarks.get(target["id"])})
    history = db.scan_history()
    current = history[-1]["readiness"] if history else None
    previous = history[-2]["readiness"] if len(history) > 1 else None
    reachable = [row for row in rows if row["reachable"]]
    roadmap = [entry for entry in (risk.roadmap_entry(row["target"], row) for row in rows) if entry]
    return {
        "read_only": config.read_only(),
        "readiness": current,
        "previous_readiness": previous,
        "history": history,
        "scanned_at": history[-1]["finished_at"] if history else None,
        "kpi": {
            "assets": len(rows),
            "reachable": len(reachable),
            "mosca_vulnerable": sum(1 for row in reachable if row["assessment"]["mosca_vulnerable"]),
            "protected": sum(1 for row in reachable if row["assessment"]["risk"] == 0),
            "critical_findings": sum(1 for row in rows for f in row["findings"] if f["severity"] == "critical"),
        },
        "rows": rows,
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
