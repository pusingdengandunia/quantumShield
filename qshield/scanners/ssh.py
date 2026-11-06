"""M1: SSH probe. Reads the server's SSH_MSG_KEXINIT without authenticating."""
from __future__ import annotations

import socket
import struct

HYBRID_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com")
_MAX_PACKET = 64 * 1024


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def _read_banner(sock: socket.socket) -> str:
    line = b""
    for _ in range(8192):
        char = _recv_exact(sock, 1)
        line += char
        if char == b"\n":
            text = line.decode("utf-8", "replace").strip()
            if text.startswith("SSH-"):
                return text
            line = b""
    raise ValueError("no SSH banner")


def parse_kexinit(packet: bytes) -> dict[str, list[str]]:
    """Parse the payload of an SSH_MSG_KEXINIT packet (type byte + cookie + name-lists)."""
    if not packet or packet[0] != 20:
        raise ValueError("not a KEXINIT packet")
    offset = 17
    names = []
    for _ in range(2):  # kex_algorithms, server_host_key_algorithms
        length = struct.unpack_from(">I", packet, offset)[0]
        offset += 4
        names.append(packet[offset:offset + length].decode("ascii", "replace").split(","))
        offset += length
    return {"kex": names[0], "host_keys": names[1]}


def scan_ssh(host: str, port: int) -> dict:
    location = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            sock.settimeout(6)
            banner = _read_banner(sock)
            sock.sendall(b"SSH-2.0-QShieldProbe\r\n")
            length = struct.unpack(">I", _recv_exact(sock, 4))[0]
            if not 0 < length < _MAX_PACKET:
                raise ValueError("bad packet length")
            raw = _recv_exact(sock, length)
            payload = raw[1:length - raw[0]]
            algorithms = parse_kexinit(payload)
    except (OSError, ValueError, struct.error):
        return {"reachable": False, "items": [], "findings": [
            {"severity": "warning", "text": f"{location} tidak bisa dibaca sebagai layanan SSH."}]}

    hybrid = [name for name in algorithms["kex"] if name in HYBRID_KEX]
    classical_kex = [n for n in algorithms["kex"] if not n.startswith(("ext-info", "kex-strict")) and n not in HYBRID_KEX]
    items: list[dict] = []
    if hybrid:
        items.append({"algorithm": hybrid[0], "primitive": "kem", "role": "kex", "quantum": "safe", "nist_level": 3,
                      "param": hybrid[0], "location": location})
    elif classical_kex:
        items.append({"algorithm": classical_kex[0], "primitive": "key-agree", "role": "kex", "quantum": "vulnerable",
                      "nist_level": 0, "param": classical_kex[0], "location": location})
    for host_key in algorithms["host_keys"]:
        items.append({"algorithm": host_key, "primitive": "signature", "role": "auth", "quantum": "vulnerable",
                      "nist_level": 0, "param": host_key, "location": location})

    findings = []
    if hybrid:
        findings.append({"severity": "info", "text": f"Server menawarkan key exchange hybrid {hybrid[0]}."})
    else:
        findings.append({"severity": "critical", "text": "Tidak ada key exchange post-quantum; perbarui OpenSSH ke 9.9+ "
                                                         "dan aktifkan mlkem768x25519-sha256."})
    return {"reachable": True, "items": items, "findings": findings, "banner": banner, "kex": algorithms["kex"],
            "host_keys": algorithms["host_keys"], "hybrid": bool(hybrid)}
