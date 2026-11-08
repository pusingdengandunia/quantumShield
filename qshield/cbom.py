"""M3: export the latest scan as a CycloneDX 1.6 Cryptographic Bill of Materials."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import __version__


def _algorithm_component(reference: str, item: dict, target: str) -> dict:
    component = {
        "type": "cryptographic-asset",
        "bom-ref": reference,
        "name": item["algorithm"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": item["primitive"],
                "parameterSetIdentifier": str(item.get("param", "")),
                "nistQuantumSecurityLevel": item["nist_level"],
            },
        },
        "properties": [
            {"name": "qshield:target", "value": target},
            {"name": "qshield:role", "value": item["role"]},
            {"name": "qshield:quantum", "value": item["quantum"]},
        ],
    }
    location = item.get("location")
    if location:
        occurrence = {"location": location}
        if item.get("line"):
            occurrence["line"] = item["line"]
        component["evidence"] = {"occurrences": [occurrence]}
    return component


def build_cbom(results: list[dict]) -> dict:
    """`results` holds one stored scan result per target."""
    components = []
    for result in results:
        target = result["target_name"]
        for index, item in enumerate(result["items"]):
            reference = f"crypto-{result['target_id']}-{index}"
            components.append(_algorithm_component(reference, item, target))
        # Results stored before the PKI audit only have the leaf under "certificate".
        audit = result["detail"].get("pki") or {}
        chain = audit.get("chain") or [c for c in [result["detail"].get("certificate")] if c]
        for position, certificate in enumerate(chain):
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"cert-{result['target_id']}-{position}",
                "name": certificate["subject"] or target,
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": certificate["subject"],
                        "issuerName": certificate["issuer"],
                        "notValidBefore": certificate["not_before"],
                        "notValidAfter": certificate["not_after"],
                        "certificateFormat": "X.509",
                    },
                },
                "properties": [
                    {"name": "qshield:target", "value": target},
                    {"name": "qshield:role", "value": certificate.get("role", "leaf")},
                    {"name": "qshield:pqc", "value": str(certificate.get("pqc", False)).lower()},
                ],
            })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "Kartika Q-Shield", "version": __version__}]},
        },
        "components": components,
    }
