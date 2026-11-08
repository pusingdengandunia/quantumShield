"""M3: risk model.

    Konteks = wA + wS*S + wE*E + wM*M
    Risiko  = 100 * A * Konteks

A is the severity of the worst problem found on the asset, and the context says how much
that asset matters. A problem-free asset scores 0 without any special case, and an asset
with a classic key exchange (A = 1) scores as it did in the concept document.

Mosca (X + Y > Z) is a separate check. It only covers confidentiality, because that is
what harvest-now-decrypt-later attacks threaten.
"""
from __future__ import annotations

from datetime import date

SENSITIVITY = {
    "rahasia": {"S": 1.0, "label": "Rahasia"},
    "internal": {"S": 0.5, "label": "Internal"},
    "publik": {"S": 0.1, "label": "Publik"},
}
EXPOSURE = {
    "internet": {"E": 1.0, "label": "Internet-facing"},
    "antar-satuan": {"E": 0.6, "label": "Antar-satuan"},
    "lan": {"E": 0.3, "label": "LAN tertutup"},
}
MIGRATION = {
    "gateway": {"M": 0.4, "label": "Bisa pakai gateway"},
    "update": {"M": 0.7, "label": "Perlu update software"},
    "legacy": {"M": 1.0, "label": "Legacy/hardware"},
}
# X (years data must stay secret) and Y (years to migrate) are starting assumptions.
# Operators replace them from the dashboard and record their source in mosca_source.
DEFAULT_SETTINGS = {
    "wA": 0.40, "wS": 0.30, "wE": 0.20, "wM": 0.10, "quantum_year": 2030,
    "x_rahasia": 10, "x_internal": 5, "x_publik": 0,
    "y_gateway": 1, "y_update": 2, "y_legacy": 5,
    "mosca_source": "",
}

# code -> (severity A, explanation). The highest severity on an asset becomes its A.
DRIVERS = {
    "kex_classic": (1.0, "Key exchange klasik rentan HNDL"),
    "code_classic": (1.0, "Kode atau konfigurasi memakai kriptografi klasik"),
    "cert_weak": (0.9, "Kunci atau tanda tangan sertifikat lemah"),
    "tls_legacy": (0.7, "TLS 1.0/1.1 masih aktif"),
    "cert_expired": (0.7, "Sertifikat kedaluwarsa"),
    "cert_untrusted": (0.5, "Rantai sertifikat tidak tepercaya"),
    "hostname_mismatch": (0.5, "Sertifikat tidak cocok dengan nama host"),
    "cipher_weakened": (0.3, "AES-128 melemah terhadap algoritma Grover"),
    "direct_open": (0.3, "Gateway aktif, tetapi akses langsung masih terbuka"),
    "auth_classic": (0.2, "Autentikasi masih klasik"),
}

STATUS_LABELS = {
    "protected": "Terlindungi",
    "partial": "Terlindungi Sebagian",
    "vulnerable": "Rentan",
    "high": "Berisiko Tinggi",
    "unknown": "Tidak terjangkau",
}
PRIORITY_BY_STATUS = {"high": "P1", "vulnerable": "P2", "partial": "P3", "protected": "P4", "unknown": "-"}
PHASE_BY_PRIORITY = {"P1": "P1: segera", "P2": "P2: 6 bulan", "P3": "P3: 12 bulan"}
HIGH_RISK = 70
PARTIAL_MAX_A = 0.3
_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "-": 4}
_MIGRATION_EFFORT = {"gateway": 0, "update": 1, "legacy": 2}


def collect_drivers(items: list[dict], drivers: list[dict] | None = None) -> list[dict]:
    """Merge what the items imply with what the scanner reported, worst first."""
    codes = {driver["code"] for driver in drivers or []}
    for item in items:
        if item.get("role") == "auth":
            continue
        if item["quantum"] == "vulnerable":
            codes.add("code_classic" if item.get("role") == "code" else "kex_classic")
        elif item["quantum"] == "weakened":
            codes.add("cipher_weakened")
    return sorted(({"code": code, "A": DRIVERS[code][0], "label": DRIVERS[code][1]} for code in codes),
                  key=lambda driver: (-driver["A"], driver["code"]))


def assess(items: list[dict], sensitivity: str, exposure: str, migration: str, settings: dict,
           today: date | None = None, drivers: list[dict] | None = None) -> dict:
    today = today or date.today()
    merged = collect_drivers(items, drivers)
    a = merged[0]["A"] if merged else 0.0
    s = SENSITIVITY[sensitivity]["S"]
    e = EXPOSURE[exposure]["E"]
    m = MIGRATION[migration]["M"]
    x = settings[f"x_{sensitivity}"]
    y = settings[f"y_{migration}"]
    z = settings["quantum_year"] - today.year
    context = settings["wA"] + settings["wS"] * s + settings["wE"] * e + settings["wM"] * m
    confidentiality_exposed = any(item.get("role") != "auth" and item["quantum"] != "safe" for item in items)
    return {"risk": round(100 * a * context, 1), "A": a, "S": s, "E": e, "M": m, "X": x, "Y": y, "Z": z,
            "context": round(context, 2), "drivers": merged,
            "mosca_vulnerable": confidentiality_exposed and x + y > z}


def classify(result: dict) -> str:
    assessment = result["assessment"]
    if not result["reachable"]:
        return "unknown"
    if assessment["risk"] == 0:
        return "protected"
    hybrid = any(item.get("role") == "kex" and item["quantum"] == "safe" for item in result["items"])
    if hybrid and assessment["A"] <= PARTIAL_MAX_A:
        return "partial"
    return "high" if assessment["risk"] >= HIGH_RISK else "vulnerable"


def sort_key(row: dict) -> tuple:
    """Priority first, then risk, Mosca, exposure, and the easiest migration."""
    assessment = row["assessment"]
    target = row["target"]
    return (_PRIORITY_ORDER[row["priority"]], -assessment["risk"], not assessment["mosca_vulnerable"],
            -EXPOSURE[target["exposure"]]["E"], _MIGRATION_EFFORT[target["migration"]], row["target_name"])


def readiness(results: list[dict]) -> float | None:
    """100 minus the average risk, weighted by each asset's sensitivity."""
    scored = [r for r in results if r["reachable"]]
    total = sum(r["assessment"]["S"] for r in scored)
    if not total:
        return None
    average = sum(r["assessment"]["risk"] * r["assessment"]["S"] for r in scored) / total
    return round(100 - average, 1)


def _actions(target: dict, codes: set[str]) -> list[str]:
    actions = []
    if "kex_classic" in codes:
        if target["kind"] == "tls" and target["migration"] == "gateway":
            actions.append("Pasang PQC Gateway hybrid X25519MLKEM768 di depan layanan, lalu tutup akses langsung.")
        elif target["kind"] == "ssh":
            actions.append("Perbarui OpenSSH ke 9.9+ dan aktifkan mlkem768x25519-sha256 di KexAlgorithms.")
        else:
            actions.append("Isolasi aset di segmen terlindungi dan rencanakan penggantian perangkat.")
    if "code_classic" in codes:
        actions.append("Ganti pemanggilan RSA/ECC dengan library yang mendukung ML-KEM/ML-DSA; pindahkan private key dari repo.")
    if "tls_legacy" in codes:
        actions.append("Nonaktifkan TLS 1.0 dan 1.1.")
    if codes & {"cert_weak", "cert_expired"}:
        actions.append("Ganti sertifikat yang lemah atau kedaluwarsa.")
    if codes & {"cert_untrusted", "hostname_mismatch"}:
        actions.append("Perbaiki rantai sertifikat dan nama host, atau daftarkan CA internal.")
    if "direct_open" in codes:
        actions.append("Tutup akses langsung ke layanan lewat firewall.")
    if "cipher_weakened" in codes:
        actions.append("Prioritaskan AES-256.")
    if "auth_classic" in codes:
        actions.append("Rencanakan sertifikat ML-DSA saat CA mendukung.")
    return actions


def roadmap_entry(row: dict) -> dict | None:
    phase = PHASE_BY_PRIORITY.get(row["priority"])
    if phase is None:
        return None
    codes = {driver["code"] for driver in row["assessment"].get("drivers", [])}
    return {"target": row["target_name"], "risk": row["assessment"]["risk"], "priority": row["priority"], "phase": phase,
            "action": " ".join(_actions(row["target"], codes))}
