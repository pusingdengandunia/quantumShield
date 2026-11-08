"""M1: TLS probe. Drives the OpenSSL CLI because Python's ssl module cannot
choose or report TLS 1.3 key-exchange groups."""
from __future__ import annotations

import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .. import config
from . import pki

HYBRID_GROUP = "X25519MLKEM768"
CLASSIC_GROUP = "X25519"
_VERSION_FLAGS = {"TLSv1.3": "-tls1_3", "TLSv1.2": "-tls1_2", "TLSv1.1": "-tls1_1", "TLSv1.0": "-tls1"}
_CIPHER_RE = re.compile(r"Cipher is (\S+)")
_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group: (\S+)")
_TEMP_KEY_RE = re.compile(r"(?:Server|Peer) Temp Key: ([^,\n]+)(?:, ([^,\n]+))?, (\d+) bits")
_BYTES_RE = re.compile(r"handshake has read (\d+) bytes and written (\d+) bytes")
_SAFE_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024"}


def handshake(host: str, port: int, *flags: str, timeout: float = 8.0) -> str:
    """Run one handshake and return s_client output; never raises on TLS failure."""
    cmd = [config.openssl_bin(), "s_client", "-connect", f"{host}:{port}", "-servername", host, *flags]
    try:
        done = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    return done.stdout.decode("utf-8", "replace") + done.stderr.decode("utf-8", "replace")


def succeeded(output: str) -> bool:
    match = _CIPHER_RE.search(output)
    return bool(match) and match.group(1) != "(NONE)"


def hybrid_handshake(host: str, port: int) -> bool:
    output = handshake(host, port, "-tls1_3", "-groups", HYBRID_GROUP)
    match = _GROUP_RE.search(output)
    return succeeded(output) and bool(match) and match.group(1) == HYBRID_GROUP


def measure_handshake(host: str, port: int, group: str) -> tuple[float, int] | None:
    """Return (wall-clock ms, bytes on the wire) for one TLS 1.3 handshake."""
    start = time.perf_counter()
    output = handshake(host, port, "-tls1_3", "-groups", group)
    elapsed = (time.perf_counter() - start) * 1000
    match = _BYTES_RE.search(output)
    if not succeeded(output) or not match:
        return None
    return elapsed, int(match.group(1)) + int(match.group(2))


def _is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=4):
            return True
    except OSError:
        return False


def _cipher_item(cipher: str) -> dict | None:
    upper = cipher.upper()
    if "AES128" in upper or "AES_128" in upper:
        return {"algorithm": "AES-128", "primitive": "block-cipher", "role": "cipher", "quantum": "weakened",
                "nist_level": 1, "param": "128"}
    if "AES256" in upper or "AES_256" in upper:
        return {"algorithm": "AES-256", "primitive": "block-cipher", "role": "cipher", "quantum": "safe",
                "nist_level": 5, "param": "256"}
    if "CHACHA20" in upper:
        return {"algorithm": "ChaCha20-Poly1305", "primitive": "ae", "role": "cipher", "quantum": "safe",
                "nist_level": 5, "param": "256"}
    return None


def _kex_item(output: str, cipher: str, version: str) -> dict:
    group = _GROUP_RE.search(output)
    if group and group.group(1) != "<NULL>":
        name = group.group(1)
    else:
        temp = _TEMP_KEY_RE.search(output)
        if temp:
            # "ECDH, prime256v1, 256 bits" carries the curve in the second field.
            name = (temp.group(2) or temp.group(1)).strip()
        elif version != "TLSv1.3" and not cipher.upper().startswith(("ECDHE", "DHE")):
            name = "RSA key transport"
        else:
            name = "unknown"
    if name in _SAFE_GROUPS:
        return {"algorithm": name, "primitive": "kem", "role": "kex", "quantum": "safe", "nist_level": 3, "param": name}
    return {"algorithm": name, "primitive": "key-agree", "role": "kex", "quantum": "vulnerable", "nist_level": 0,
            "param": name}


def _trust_flags() -> tuple[str, ...]:
    """CA flags for s_client: the public bundle plus any internal CA."""
    bundle, extra = config.ca_bundle(), config.extra_ca()
    sources = [path for path in (bundle, extra) if path and path.is_file()]
    if not sources:
        return ()
    if len(sources) == 1:
        return ("-CAfile", str(sources[0]))
    merged = Path(tempfile.gettempdir()) / "qshield-trust.pem"
    merged.write_bytes(b"\n".join(path.read_bytes() for path in sources))
    return ("-CAfile", str(merged))


def scan_tls(host: str, port: int) -> dict:
    if not _is_open(host, port):
        return {"reachable": False, "items": [], "findings": [
            {"severity": "warning", "text": f"{host}:{port} tidak bisa dihubungi."}]}

    # SECLEVEL=0 so the probe can still complete against deliberately weak servers.
    weak_ok = ("-cipher", "ALL:@SECLEVEL=0")
    versions = []
    for version, flag in _VERSION_FLAGS.items():
        extra = () if version == "TLSv1.3" else weak_ok
        if succeeded(handshake(host, port, flag, *extra)):
            versions.append(version)
    if not versions:
        # Not "reachable": with no items the asset would otherwise score as protected.
        return {"reachable": False, "items": [], "findings": [
            {"severity": "warning", "text": f"{host}:{port} terbuka tetapi handshake TLS gagal dinegosiasi."}]}

    best = versions[0]
    extra = () if best == "TLSv1.3" else weak_ok
    output = handshake(host, port, _VERSION_FLAGS[best], *extra, "-showcerts", *_trust_flags())
    cipher = (_CIPHER_RE.search(output) or [None, "unknown"])[1]
    hybrid = hybrid_handshake(host, port) if best == "TLSv1.3" else False

    location = f"{host}:{port}"
    audit = pki.analyze(output, host)
    items: list[dict] = []
    findings: list[dict] = list(audit["findings"])
    drivers: list[dict] = list(audit["drivers"])

    kex = _kex_item(output, cipher, best)
    if hybrid:
        kex = {"algorithm": HYBRID_GROUP, "primitive": "kem", "role": "kex", "quantum": "safe", "nist_level": 3,
               "param": HYBRID_GROUP}
    items.append({**kex, "location": location})
    cipher_item = _cipher_item(cipher)
    if cipher_item:
        items.append({**cipher_item, "location": location})

    leaf = audit["pki"]["chain"][0] if audit["pki"] else None
    if leaf:
        items.append({"algorithm": leaf["key_algorithm"], "primitive": "signature", "role": "auth",
                      "quantum": "safe" if leaf["pqc"] else "vulnerable", "nist_level": leaf["nist_level"],
                      "param": str(leaf["key_size"] or leaf["key_algorithm"]), "location": location})

    if hybrid:
        findings.insert(0, {"severity": "info", "text": f"Handshake hybrid {HYBRID_GROUP} berhasil; aman dari HNDL."})
    else:
        findings.insert(0, {"severity": "critical", "text": f"Key exchange {kex['algorithm']} rentan algoritma Shor; "
                                                            "trafik bisa disadap sekarang dan didekripsi nanti (HNDL)."})
    legacy = [old for old in ("TLSv1.0", "TLSv1.1") if old in versions]
    if legacy:
        drivers.append({"code": "tls_legacy"})
    for old in legacy:
        findings.append({"severity": "critical", "text": f"{old} masih aktif; protokol ini sudah usang."})
    if "TLSv1.3" not in versions:
        findings.append({"severity": "warning", "text": "TLS 1.3 tidak didukung; hybrid ML-KEM butuh TLS 1.3."})

    return {"reachable": True, "items": items, "findings": findings, "drivers": drivers, "versions": versions,
            "cipher": cipher, "hybrid": hybrid, "pki": audit["pki"]}
