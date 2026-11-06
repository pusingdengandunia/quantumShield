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


def test_roadmap_skips_protected_assets_and_picks_action_by_kind():
    ssh = {"name": "ssh", "kind": "ssh", "migration": "update"}
    assert "OpenSSH" in risk.roadmap_entry(ssh, {"reachable": True, "assessment": {"risk": 83.0}})["action"]
    assert risk.roadmap_entry(ssh, {"reachable": True, "assessment": {"risk": 0.0}}) is None
