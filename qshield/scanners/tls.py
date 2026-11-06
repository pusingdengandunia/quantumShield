"""M1: TLS probe. Drives the OpenSSL CLI because Python's ssl module cannot
choose or report TLS 1.3 key-exchange groups."""
from __future__ import annotations

import re
import socket
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .. import config

HYBRID_GROUP = "X25519MLKEM768"
CLASSIC_GROUP = "X25519"
_VERSION_FLAGS = {"TLSv1.3": "-tls1_3", "TLSv1.2": "-tls1_2", "TLSv1.1": "-tls1_1", "TLSv1.0": "-tls1"}
_CIPHER_RE = re.compile(r"Cipher is (\S+)")
_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group: (\S+)")
_TEMP_KEY_RE = re.compile(r"(?:Server|Peer) Temp Key: ([^,\n]+)(?:, ([^,\n]+))?, (\d+) bits")
_BYTES_RE = re.compile(r"handshake has read (\d+) bytes and written (\d+) bytes")
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
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


def describe_certificate(pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(pem.encode())
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm, size = f"ECDSA-{key.curve.name}", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        algorithm, size = "Ed25519", 255
    elif isinstance(key, ed448.Ed448PublicKey):
        algorithm, size = "Ed448", 448
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, size = "DSA", key.key_size
    else:
        algorithm, size = cert.public_key_algorithm_oid.dotted_string, 0
    return {
        "algorithm": algorithm,
        "size": size,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "signature": cert.signature_algorithm_oid._name,
    }


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
    output = handshake(host, port, _VERSION_FLAGS[best], *extra)
    cipher = (_CIPHER_RE.search(output) or [None, "unknown"])[1]
    hybrid = hybrid_handshake(host, port) if best == "TLSv1.3" else False

    items: list[dict] = []
    findings: list[dict] = []
    location = f"{host}:{port}"

    kex = _kex_item(output, cipher, best)
    if hybrid:
        kex = {"algorithm": HYBRID_GROUP, "primitive": "kem", "role": "kex", "quantum": "safe", "nist_level": 3,
               "param": HYBRID_GROUP}
    items.append({**kex, "location": location})
    cipher_item = _cipher_item(cipher)
    if cipher_item:
        items.append({**cipher_item, "location": location})

    cert_info = None
    pem = _PEM_RE.search(output)
    if pem:
        cert_info = describe_certificate(pem.group(0))
        items.append({"algorithm": cert_info["algorithm"], "primitive": "signature", "role": "auth",
                      "quantum": "vulnerable", "nist_level": 0, "param": str(cert_info["size"]),
                      "location": location})

    if hybrid:
        findings.append({"severity": "info", "text": f"Handshake hybrid {HYBRID_GROUP} berhasil; aman dari HNDL."})
        findings.append({"severity": "info", "text": "Sertifikat masih klasik: autentikasi perlu ML-DSA saat CA mendukung."})
    else:
        findings.append({"severity": "critical", "text": f"Key exchange {kex['algorithm']} rentan algoritma Shor; "
                                                         "trafik bisa disadap sekarang dan didekripsi nanti (HNDL)."})
    if cert_info and cert_info["algorithm"] == "RSA" and cert_info["size"] < 2048:
        findings.append({"severity": "critical", "text": f"Sertifikat RSA-{cert_info['size']} lemah bahkan terhadap komputer klasik."})
    for old in ("TLSv1.0", "TLSv1.1"):
        if old in versions:
            findings.append({"severity": "critical", "text": f"{old} masih aktif; protokol ini sudah usang."})
    if "TLSv1.3" not in versions:
        findings.append({"severity": "warning", "text": "TLS 1.3 tidak didukung; hybrid ML-KEM butuh TLS 1.3."})

    return {"reachable": True, "items": items, "findings": findings, "versions": versions, "cipher": cipher,
            "hybrid": hybrid, "certificate": cert_info}
