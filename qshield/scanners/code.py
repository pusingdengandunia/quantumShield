"""M2: code and configuration scanner. Rule-based and offline.

Key material is never copied into results: only path, line and rule are stored.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor"}
_MAX_FILE_BYTES = 1024 * 1024
_CODE_EXT = {".py", ".java", ".js", ".ts", ".go"}


def _rule(algorithm: str, primitive: str, pattern: str, text: str, severity: str = "warning") -> dict:
    return {"algorithm": algorithm, "primitive": primitive, "pattern": re.compile(pattern), "text": text,
            "severity": severity}


CODE_RULES = [
    _rule("RSA", "pke", r"rsa\.generate_private_key|RSA\.generate\(|rsa\.newkeys\(", "Pembuatan kunci RSA di kode"),
    _rule("ECC", "signature", r"ec\.generate_private_key|ECC\.generate\(", "Pembuatan kunci ECC di kode"),
    _rule("DH", "key-agree", r"dh\.generate_parameters|DiffieHellman\b", "Pemakaian Diffie-Hellman di kode"),
    _rule("RSA", "pke", r"KeyPairGenerator\.getInstance\(\s*\"RSA\"|Cipher\.getInstance\(\s*\"RSA", "Pemakaian RSA di Java"),
    _rule("ECC", "signature", r"KeyPairGenerator\.getInstance\(\s*\"EC\"|Signature\.getInstance\(\s*\"\w*ECDSA", "Pemakaian ECC di Java"),
    _rule("RSA", "pke", r"generateKeyPair(Sync)?\(\s*['\"]rsa['\"]|publicEncrypt\(", "Pemakaian RSA di Node.js"),
    _rule("ECC", "signature", r"generateKeyPair(Sync)?\(\s*['\"]ec['\"]|createECDH\(", "Pemakaian ECC di Node.js"),
    _rule("RSA", "pke", r"rsa\.GenerateKey\(|rsa\.EncryptOAEP\(|rsa\.EncryptPKCS1v15\(", "Pemakaian RSA di Go"),
    _rule("ECC", "signature", r"ecdsa\.GenerateKey\(|elliptic\.P(224|256|384|521)\(", "Pemakaian ECC di Go"),
]

NGINX_RULES = [
    _rule("TLS-legacy", "other", r"^\s*ssl_protocols\b.*\bTLSv1(\.1)?(\s|;)", "nginx masih mengaktifkan TLS usang", "critical"),
    _rule("RSA", "signature", r"^\s*ssl_certificate\s+.*rsa", "nginx memakai sertifikat RSA"),
    _rule("ECDH", "key-agree", r"^\s*ssl_ecdh_curve\s+(?!.*MLKEM)", "ssl_ecdh_curve tanpa grup hybrid ML-KEM"),
]

SSHD_RULES = [
    _rule("RSA", "signature", r"^\s*HostKey\s+.*ssh_host_rsa_key", "OpenSSH memakai host key RSA"),
    _rule("ECDSA", "signature", r"^\s*HostKey\s+.*ssh_host_ecdsa_key", "OpenSSH memakai host key ECDSA"),
    _rule("ECDH", "key-agree", r"^\s*KexAlgorithms\s+(?!.*(mlkem|sntrup))", "KexAlgorithms OpenSSH tanpa hybrid post-quantum"),
]

_PEM_KEYS = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "ECC",
    "DSA PRIVATE KEY": "DSA",
    "OPENSSH PRIVATE KEY": "OpenSSH key",
    "PRIVATE KEY": "PKCS#8 key",
}
_PEM_RE = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----")


def _rules_for(path: Path) -> list[dict]:
    name = path.name.lower()
    if path.suffix.lower() in _CODE_EXT:
        return CODE_RULES
    if "nginx" in name:
        return NGINX_RULES
    if name in {"sshd_config", "sshd.conf"}:
        return SSHD_RULES
    return []


def _iter_files(root: Path):
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            path = Path(folder) / name
            if path.is_symlink():
                continue
            try:
                if path.stat().st_size <= _MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def scan_code(root: str | Path) -> dict:
    root = Path(root)
    if not root.is_dir():
        return {"reachable": False, "items": [], "findings": [
            {"severity": "warning", "text": f"Folder {root} tidak ditemukan."}]}

    items: list[dict] = []
    findings: list[dict] = []
    files = 0
    for path in _iter_files(root):
        try:
            text = path.read_text("utf-8", "ignore")
        except OSError:
            continue
        files += 1
        relative = path.relative_to(root).as_posix()
        rules = _rules_for(path)
        for number, line in enumerate(text.splitlines(), 1):
            pem = _PEM_RE.search(line)
            if pem:
                algorithm = _PEM_KEYS.get(pem.group(1), "Private key")
                items.append({"algorithm": algorithm, "primitive": "signature", "role": "code", "quantum": "vulnerable",
                              "nist_level": 0, "param": "private-key", "location": relative, "line": number})
                findings.append({"severity": "critical", "text": f"Private key {algorithm} tersimpan di {relative}:{number}."})
                continue
            for rule in rules:
                if rule["pattern"].search(line):
                    items.append({"algorithm": rule["algorithm"], "primitive": rule["primitive"], "role": "code",
                                  "quantum": "vulnerable", "nist_level": 0, "param": rule["algorithm"],
                                  "location": relative, "line": number})
                    findings.append({"severity": rule["severity"], "text": f"{rule['text']} ({relative}:{number})."})
    return {"reachable": True, "items": items, "findings": findings, "files_scanned": files}
