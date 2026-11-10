"""M1: PKI audit. Reads the certificate chain a server presents and reports whether
its signatures are ready for post-quantum cryptography."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_VERIFICATION_RE = re.compile(r"^Verification( error)?: ?(.*)$", re.M)
_VERIFY_CODE_RE = re.compile(r"Verify return code: (.+)")
_PEER_SIGNATURE_RE = re.compile(r"Peer signature type: (\S+)")
EXPIRY_WARNING_DAYS = 30

# name -> NIST security level. ML-DSA and SLH-DSA OIDs are the NIST standard arc.
# Falcon has no final standard: these are the open-quantum-safe provider's OIDs, which may
# still change, and nothing in the lab can exercise them end to end.
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", 2),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", 3),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", 5),
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA-SHA2-128s", 1),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA-SHA2-128f", 1),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA-SHA2-192s", 3),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA-SHA2-192f", 3),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA-SHA2-256s", 5),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA-SHA2-256f", 5),
    "2.16.840.1.101.3.4.3.26": ("SLH-DSA-SHAKE-128s", 1),
    "2.16.840.1.101.3.4.3.27": ("SLH-DSA-SHAKE-128f", 1),
    "2.16.840.1.101.3.4.3.28": ("SLH-DSA-SHAKE-192s", 3),
    "2.16.840.1.101.3.4.3.29": ("SLH-DSA-SHAKE-192f", 3),
    "2.16.840.1.101.3.4.3.30": ("SLH-DSA-SHAKE-256s", 5),
    "2.16.840.1.101.3.4.3.31": ("SLH-DSA-SHAKE-256f", 5),
    "1.3.9999.3.11": ("Falcon-512", 1),
    "1.3.9999.3.16": ("Falcon-padded-512", 1),
    "1.3.9999.3.14": ("Falcon-1024", 5),
    "1.3.9999.3.19": ("Falcon-padded-1024", 5),
}


def _key_details(cert: x509.Certificate) -> tuple[str, int, bool, int]:
    """Return (algorithm, size, is_pqc, NIST level) for the certificate's public key."""
    oid = cert.public_key_algorithm_oid.dotted_string
    if oid in PQC_OIDS:
        name, level = PQC_OIDS[oid]
        return name, 0, True, level
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return oid, 0, False, 0
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, False, 0
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{key.curve.name}", key.key_size, False, 0
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 255, False, 0
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448, False, 0
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, False, 0
    return oid, 0, False, 0


def _signature_details(cert: x509.Certificate) -> tuple[str, bool]:
    oid = cert.signature_algorithm_oid
    if oid.dotted_string in PQC_OIDS:
        return PQC_OIDS[oid.dotted_string][0], True
    name = oid._name
    return (oid.dotted_string if name == "Unknown OID" else name), False


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _subject_names(cert: x509.Certificate, limit: int = 10) -> list[str]:
    """DNS names and IP addresses the certificate is valid for, so a hostname
    mismatch can show which names the server actually presented."""
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    values = names.get_values_for_type(x509.DNSName) + [str(ip) for ip in names.get_values_for_type(x509.IPAddress)]
    return values[:limit]


def describe_certificate(pem: str, position: int = 0, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_pem_x509_certificate(pem.encode())
    key_algorithm, key_size, key_pqc, level = _key_details(cert)
    signature, signature_pqc = _signature_details(cert)
    self_signed = cert.subject == cert.issuer
    is_ca = _is_ca(cert)
    if position == 0 and not (self_signed and is_ca):
        role = "leaf"
    elif self_signed:
        role = "root"
    else:
        role = "intermediate"
    return {
        "position": position,
        "role": role,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "names": _subject_names(cert),
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": signature,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_left": (cert.not_valid_after_utc - now).days,
        "is_ca": is_ca,
        "self_signed": self_signed,
        "pqc": key_pqc and signature_pqc,
        "nist_level": level,
    }


def hostname_matches(pem: str, host: str) -> bool:
    """Check the leaf's subjectAltName only, as modern clients do; the CN is ignored."""
    cert = x509.load_pem_x509_certificate(pem.encode())
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return address in names.get_values_for_type(x509.IPAddress)
    host = host.lower().rstrip(".")
    for name in names.get_values_for_type(x509.DNSName):
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _strength(entry: dict) -> int:
    """Rough classical security bits, used only to name the chain's weakest link."""
    if entry["pqc"]:
        return 1000
    size, algorithm = entry["key_size"], entry["key_algorithm"]
    if algorithm in {"RSA", "DSA"}:
        return 80 if size < 2048 else 112 if size < 3072 else 128 if size < 4096 else 140
    if algorithm.startswith("ECDSA") or algorithm.startswith("Ed"):
        return size // 2
    return 0


def _weak_key(entry: dict) -> bool:
    algorithm, size = entry["key_algorithm"], entry["key_size"]
    if algorithm in {"RSA", "DSA"}:
        return size < 2048
    return algorithm.startswith("ECDSA") and size < 224


def _weak_signature(entry: dict) -> bool:
    name = entry["signature_algorithm"].lower()
    # A root's own signature is not checked by clients, so only issued certificates count.
    return entry["role"] != "root" and ("sha1" in name or "md5" in name)


def _describe_key(entry: dict) -> str:
    size = entry["key_size"]
    return f"{entry['key_algorithm']}-{size}" if entry["key_algorithm"] in {"RSA", "DSA"} else entry["key_algorithm"]


def analyze(output: str, host: str, now: datetime | None = None) -> dict:
    """Turn `s_client -showcerts` output into the PKI report, findings and risk drivers."""
    pems = _PEM_RE.findall(output)
    if not pems:
        return {"pki": None, "findings": [{"severity": "warning", "text": "Server tidak mengirim sertifikat."}],
                "drivers": [{"code": "cert_untrusted"}]}

    chain = [describe_certificate(pem, position, now) for position, pem in enumerate(pems)]
    match = _VERIFICATION_RE.search(output)
    verified = None if match is None else match.group(1) is None and match.group(2).strip() == "OK"
    code = _VERIFY_CODE_RE.search(output)
    trust = {"verified": verified, "code": code.group(1).strip() if code else None,
             "hostname_match": hostname_matches(pems[0], host)}
    pqc_count = sum(1 for entry in chain if entry["pqc"])
    status = "pqc" if pqc_count == len(chain) else "mixed" if pqc_count else "classic"
    weakest = min(chain, key=_strength)
    peer_signature = _PEER_SIGNATURE_RE.search(output)
    pki = {
        "auth_status": status,
        "weakest_link": None if status == "pqc" else f"{_describe_key(weakest)} ({weakest['role']})",
        "negotiated_signature": peer_signature.group(1) if peer_signature else None,
        "root_in_chain": any(entry["role"] == "root" for entry in chain),
        "trust": trust,
        "chain": chain,
    }

    findings: list[dict] = []
    drivers: list[dict] = []
    if status != "pqc":
        drivers.append({"code": "auth_classic"})
        findings.append({"severity": "warning", "text": f"Autentikasi belum PQC; rantai terlemah {pki['weakest_link']}. "
                                                        "Tanda tangan klasik bisa dipalsukan saat komputer kuantum siap."})
    else:
        findings.append({"severity": "info", "text": f"Seluruh rantai memakai tanda tangan PQC ({chain[0]['key_algorithm']})."})

    for entry in chain:
        label = f"Sertifikat {entry['role']}"
        if _weak_key(entry) and not any(d["code"] == "cert_weak" for d in drivers):
            drivers.append({"code": "cert_weak"})
        if _weak_key(entry):
            findings.append({"severity": "critical", "text": f"{label} {_describe_key(entry)} lemah bahkan terhadap komputer klasik."})
        if _weak_signature(entry):
            if not any(d["code"] == "cert_weak" for d in drivers):
                drivers.append({"code": "cert_weak"})
            findings.append({"severity": "critical", "text": f"{label} ditandatangani {entry['signature_algorithm']} yang sudah usang."})
        if entry["days_left"] < 0:
            if not any(d["code"] == "cert_expired" for d in drivers):
                drivers.append({"code": "cert_expired"})
            findings.append({"severity": "critical", "text": f"{label} sudah kedaluwarsa."})
        elif entry["days_left"] <= EXPIRY_WARNING_DAYS:
            findings.append({"severity": "warning", "text": f"{label} kedaluwarsa dalam {entry['days_left']} hari."})

    if verified is False:
        drivers.append({"code": "cert_untrusted"})
        findings.append({"severity": "warning", "text": f"Rantai sertifikat tidak tepercaya ({trust['code']}). "
                                                        "CA internal perlu didaftarkan lewat QSHIELD_EXTRA_CA."})
    elif verified is None:
        findings.append({"severity": "info", "text": "Kepercayaan rantai tidak bisa diperiksa."})
    if not trust["hostname_match"]:
        drivers.append({"code": "hostname_mismatch"})
        findings.append({"severity": "warning", "text": f"Sertifikat tidak mencakup nama {host}."})
    return {"pki": pki, "findings": findings, "drivers": drivers}
