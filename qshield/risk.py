"""M3: risk model from the concept document, section 5.

Risk = 100 * (wA*A + wS*S + wE*E + wM*M), plus a Mosca check X + Y > Z.

One deliberate addition to the document: an asset with A = 0 has no
quantum-vulnerable confidentiality left, so its risk is 0. Without this rule a
protected secret asset keeps a high score from S and E, and the readiness score
can never reach 100.
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


def algorithm_factor(items: list[dict]) -> float:
    """A: how exposed confidentiality is. Signatures do not enable harvest-now attacks,
    so `auth` items alone do not raise it; they are reported as findings instead."""
    relevant = [item for item in items if item.get("role") != "auth"]
    if any(item["quantum"] == "vulnerable" for item in relevant):
        return 1.0
    if any(item["quantum"] == "weakened" for item in relevant):
        return 0.3
    return 0.0


def assess(items: list[dict], sensitivity: str, exposure: str, migration: str, settings: dict,
           today: date | None = None) -> dict:
    today = today or date.today()
    a = algorithm_factor(items)
    s = SENSITIVITY[sensitivity]["S"]
    e = EXPOSURE[exposure]["E"]
    m = MIGRATION[migration]["M"]
    x = settings[f"x_{sensitivity}"]
    y = settings[f"y_{migration}"]
    z = settings["quantum_year"] - today.year
    weighted = settings["wA"] * a + settings["wS"] * s + settings["wE"] * e + settings["wM"] * m
    risk = 0.0 if a == 0 else round(100 * weighted, 1)
    return {"risk": risk, "A": a, "S": s, "E": e, "M": m, "X": x, "Y": y, "Z": z,
            "mosca_vulnerable": a > 0 and x + y > z}


def readiness(results: list[dict]) -> float | None:
    """100 minus the average risk, weighted by each asset's sensitivity."""
    scored = [r for r in results if r["reachable"]]
    total = sum(r["assessment"]["S"] for r in scored)
    if not total:
        return None
    average = sum(r["assessment"]["risk"] * r["assessment"]["S"] for r in scored) / total
    return round(100 - average, 1)


def roadmap_entry(target: dict, result: dict) -> dict | None:
    risk = result["assessment"]["risk"]
    if not result["reachable"] or risk == 0:
        return None
    phase = "Fase 1: segera" if risk >= 70 else "Fase 2: 6 bulan" if risk >= 40 else "Fase 3: 12 bulan"
    if target["kind"] == "tls" and target["migration"] == "gateway":
        action = "Pasang PQC Gateway hybrid X25519MLKEM768 di depan layanan, lalu tutup akses langsung."
    elif target["kind"] == "ssh":
        action = "Perbarui OpenSSH ke 9.9+ dan aktifkan mlkem768x25519-sha256 di KexAlgorithms."
    elif target["kind"] == "repo":
        action = "Ganti pemanggilan RSA/ECC dengan library yang mendukung ML-KEM/ML-DSA; pindahkan private key dari repo."
    else:
        action = "Isolasi aset di segmen terlindungi dan rencanakan penggantian perangkat."
    return {"target": target["name"], "risk": risk, "phase": phase, "action": action}
