"""M5 and M6: PQC gateway routes and the classic-versus-hybrid benchmark.

The application only writes route files to a shared folder. A watcher inside the
gateway container validates them with `nginx -t` and reloads. This keeps the
Docker socket out of the application.
"""
from __future__ import annotations

import statistics
import time

from . import config
from .scanners import tls

_ROUTE = """server {{
    listen {port} ssl;
    ssl_certificate /etc/gateway/tls/cert.pem;
    ssl_certificate_key /etc/gateway/tls/key.pem;
    ssl_protocols TLSv1.3 TLSv1.2;
    # Hybrid first; classic groups stay as a fallback for older clients.
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
    location / {{
        proxy_pass https://{host}:{upstream_port};
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""


class GatewayError(RuntimeError):
    pass


def render_route(port: int, host: str, upstream_port: int) -> str:
    return _ROUTE.format(port=port, host=host, upstream_port=upstream_port)


def _route_file(target_id: int):
    return config.gateway_conf_dir() / f"route-{target_id}.conf"


def apply_route(target: dict, used_ports: set[int]) -> int:
    """Write the nginx route for a target and return its gateway port."""
    if config.gateway_conf_dir() is None:
        raise GatewayError("Gateway belum dikonfigurasi (QSHIELD_GATEWAY_CONF kosong).")
    free = [port for port in config.gateway_ports() if port not in used_ports]
    if target.get("gateway_port"):
        port = target["gateway_port"]
    elif free:
        port = free[0]
    else:
        raise GatewayError("Semua port gateway sudah terpakai.")
    path = _route_file(target["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(render_route(port, target["host"], target["port"]), encoding="utf-8")
    temporary.replace(path)
    return port


def remove_route(target_id: int) -> None:
    if config.gateway_conf_dir() is not None:
        _route_file(target_id).unlink(missing_ok=True)


def wait_for_hybrid(port: int, seconds: float = 15.0) -> bool:
    """Protection only counts once a real hybrid handshake succeeds."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if tls.hybrid_handshake(config.gateway_host(), port):
            return True
        time.sleep(1)
    return False


def benchmark(host: str, port: int, rounds: int = 30) -> dict:
    """Median handshake time and bytes per group. Time includes starting the
    openssl process, which both groups pay, so compare the gap and not the absolute value."""
    measured = {}
    for group in (tls.CLASSIC_GROUP, tls.HYBRID_GROUP):
        samples = [tls.measure_handshake(host, port, group) for _ in range(rounds)]
        samples = [sample for sample in samples if sample]
        if not samples:
            raise GatewayError(f"Handshake {group} gagal pada {host}:{port}.")
        measured[group] = {
            "median_ms": round(statistics.median(sample[0] for sample in samples), 2),
            "bytes": int(statistics.median(sample[1] for sample in samples)),
            "samples": len(samples),
        }
    classic, hybrid = measured[tls.CLASSIC_GROUP], measured[tls.HYBRID_GROUP]
    return {
        "classic_group": tls.CLASSIC_GROUP,
        "hybrid_group": tls.HYBRID_GROUP,
        "classic": classic,
        "hybrid": hybrid,
        "extra_ms": round(hybrid["median_ms"] - classic["median_ms"], 2),
        "extra_bytes": hybrid["bytes"] - classic["bytes"],
    }
