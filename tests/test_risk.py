from datetime import date

from qshield import risk

VULNERABLE_KEX = {"role": "kex", "quantum": "vulnerable"}
SAFE_KEX = {"role": "kex", "quantum": "safe"}
CLASSIC_CERT = {"role": "auth", "quantum": "vulnerable"}
TODAY = date(2026, 11, 4)


def assess(items, sensitivity="rahasia", exposure="antar-satuan", migration="gateway"):
    return risk.assess(items, sensitivity, exposure, migration, risk.DEFAULT_SETTINGS, today=TODAY)


def test_formula_matches_the_concept_document():
    # 100 * (0.40*1.0 + 0.30*1.0 + 0.20*0.6 + 0.10*0.4)
    assert assess([VULNERABLE_KEX])["risk"] == 86.0


def test_classic_certificate_alone_does_not_count_as_harvest_risk():
    result = assess([SAFE_KEX, CLASSIC_CERT])
    assert result["A"] == 0
    assert result["risk"] == 0
    assert result["mosca_vulnerable"] is False


def test_weakened_cipher_scores_lower_than_vulnerable_key_exchange():
    weak = assess([SAFE_KEX, {"role": "cipher", "quantum": "weakened"}])
    assert weak["A"] == 0.3
    assert 0 < weak["risk"] < assess([VULNERABLE_KEX])["risk"]


def test_mosca_compares_shelf_life_plus_migration_with_time_left():
    secret = assess([VULNERABLE_KEX])
    assert (secret["X"], secret["Y"], secret["Z"]) == (10, 1, 4)
    assert secret["mosca_vulnerable"] is True
    public = assess([VULNERABLE_KEX], sensitivity="publik")
    assert public["X"] + public["Y"] == 1
    assert public["mosca_vulnerable"] is False


def test_mosca_uses_configured_x_and_y_without_changing_risk():
    default = assess([VULNERABLE_KEX])
    settings = {**risk.DEFAULT_SETTINGS, "x_rahasia": 2, "y_gateway": 1}
    changed = risk.assess([VULNERABLE_KEX], "rahasia", "antar-satuan", "gateway", settings, today=TODAY)
    assert (changed["X"], changed["Y"]) == (2, 1)
    assert changed["mosca_vulnerable"] is False
    assert changed["risk"] == default["risk"]


def test_readiness_ignores_unreachable_assets_and_weights_by_sensitivity():
    rows = [
        {"reachable": True, "assessment": {"risk": 80.0, "S": 1.0}},
        {"reachable": True, "assessment": {"risk": 0.0, "S": 0.5}},
        {"reachable": False, "assessment": {"risk": 0.0, "S": 1.0}},
    ]
    assert risk.readiness(rows) == round(100 - 80 / 1.5, 1)
    assert risk.readiness([rows[2]]) is None


def row(priority, risk_value, *codes, kind="ssh", migration="update"):
    return {"target_name": "aset", "priority": priority, "target": {"kind": kind, "migration": migration},
            "assessment": {"risk": risk_value, "drivers": [{"code": code} for code in codes]}}


def test_roadmap_skips_protected_assets_and_picks_action_by_problem():
    assert "OpenSSH" in risk.roadmap_entry(row("P1", 83.0, "kex_classic"))["action"]
    assert risk.roadmap_entry(row("P4", 0.0)) is None
    assert risk.roadmap_entry(row("-", 0.0)) is None
    legacy = risk.roadmap_entry(row("P2", 65.8, "tls_legacy", "auth_classic", kind="tls", migration="gateway"))
    assert "Nonaktifkan TLS 1.0 dan 1.1" in legacy["action"]
    assert "ML-DSA" in legacy["action"]
    assert "Gateway" not in legacy["action"], "a hybrid service does not need the gateway"


def test_priority_sorting_uses_tie_breakers():
    def entry(name, priority, risk_value, mosca=False, exposure="lan", migration="update"):
        return {"target_name": name, "priority": priority, "assessment": {"risk": risk_value, "mosca_vulnerable": mosca},
                "target": {"exposure": exposure, "migration": migration}}

    rows = [
        entry("unknown", "-", 0),
        entry("p2", "P2", 65),
        entry("p1-low", "P1", 70),
        entry("p1-high", "P1", 86),
        entry("tie-plain", "P2", 50),
        entry("tie-mosca", "P2", 50, mosca=True),
        entry("tie-internet", "P2", 40, exposure="internet"),
        entry("tie-gateway", "P2", 40, exposure="internet", migration="gateway"),
    ]
    ordered = [r["target_name"] for r in sorted(rows, key=risk.sort_key)]
    assert ordered == ["p1-high", "p1-low", "p2", "tie-mosca", "tie-plain", "tie-gateway", "tie-internet", "unknown"]


def test_every_driver_code_a_scanner_emits_is_known():
    assert risk.collect_drivers([], [{"code": code} for code in risk.DRIVERS])
    assert risk.PRIORITY_BY_STATUS.keys() == risk.STATUS_LABELS.keys()
