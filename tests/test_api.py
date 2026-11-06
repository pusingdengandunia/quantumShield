import json
import socket

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from fastapi.testclient import TestClient

from qshield import gateway, service


def tls_target(**overrides):
    return {"name": "portal", "kind": "tls", "host": "127.0.0.1", "port": 443, "sensitivity": "rahasia",
            "exposure": "lan", "migration": "gateway", "authorized": True, **overrides}


def repo_target(path, **overrides):
    return {"name": "repo", "kind": "repo", "path": str(path), "sensitivity": "internal", "exposure": "lan",
            "migration": "update", "authorized": True, **overrides}


def test_write_without_custom_header_is_refused(client):
    assert TestClient(client.app).post("/api/scans").status_code == 403


def test_token_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("QSHIELD_API_TOKEN", "rahasia")
    assert client.post("/api/scans").status_code == 401
    assert client.post("/api/scans", headers={"X-QShield-Token": "rahasia"}).status_code == 201


def test_read_only_mode_refuses_writes_but_serves_data(client, monkeypatch):
    monkeypatch.setenv("QSHIELD_READ_ONLY", "1")
    assert client.post("/api/scans").status_code == 403
    assert client.post("/api/targets", json=tls_target()).status_code == 403
    assert client.get("/api/dashboard").json()["read_only"] is True


def test_target_needs_authorization_confirmation(client):
    assert client.post("/api/targets", json=tls_target(authorized=False)).status_code == 422


def test_public_address_is_refused_by_default(client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("8.8.8.8", 0))])
    response = client.post("/api/targets", json=tls_target(host="example.test"))
    assert response.status_code == 400
    assert "publik" in response.json()["detail"]


def test_public_address_is_accepted_when_enabled(client, monkeypatch):
    monkeypatch.setenv("QSHIELD_ALLOW_PUBLIC", "1")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("8.8.8.8", 0))])
    assert client.post("/api/targets", json=tls_target(host="example.test")).status_code == 201
    assert client.post("/api/targets", json=tls_target(name="b", host="example.test", authorized=False)).status_code == 422
    assert client.post("/api/targets", json=tls_target(name="c", host="a;}evil")).status_code == 400


def test_host_cannot_inject_nginx_configuration(client):
    assert client.post("/api/targets", json=tls_target(host="a;}evil")).status_code == 400


def test_repo_path_cannot_leave_the_root(client, tmp_path):
    assert client.post("/api/targets", json=repo_target(tmp_path.parent)).status_code == 400
    assert client.post("/api/targets", json=repo_target(tmp_path / ".." / "..")).status_code == 400
    assert client.post("/api/targets", json=repo_target(tmp_path)).status_code == 201


def test_ssh_cannot_use_the_gateway(client):
    body = tls_target(kind="ssh", port=22)
    assert client.post("/api/targets", json=body).status_code == 400


def test_gateway_refused_for_legacy_assets(client):
    target_id = client.post("/api/targets", json=tls_target(migration="legacy")).json()["id"]
    assert client.post(f"/api/targets/{target_id}/gateway").status_code == 400


def test_gateway_needs_configuration(client):
    target_id = client.post("/api/targets", json=tls_target()).json()["id"]
    assert client.post(f"/api/targets/{target_id}/gateway").status_code == 409


def test_gateway_route_is_only_active_after_a_real_hybrid_handshake(client, tmp_path, monkeypatch):
    monkeypatch.setenv("QSHIELD_GATEWAY_CONF", str(tmp_path / "conf"))
    monkeypatch.setattr(gateway, "wait_for_hybrid", lambda port: False)
    target_id = client.post("/api/targets", json=tls_target()).json()["id"]
    result = client.post(f"/api/targets/{target_id}/gateway").json()
    assert result == {"port": 9443, "status": "gagal"}
    route = (tmp_path / "conf" / f"route-{target_id}.conf").read_text()
    assert "listen 9443 ssl" in route
    assert "ssl_ecdh_curve X25519MLKEM768:X25519" in route
    assert "proxy_pass https://127.0.0.1:443" in route
    client.delete(f"/api/targets/{target_id}/gateway")
    assert not (tmp_path / "conf" / f"route-{target_id}.conf").exists()


SETTINGS = {"wA": 0.4, "wS": 0.3, "wE": 0.2, "wM": 0.1, "quantum_year": 2030, "x_rahasia": 10, "x_internal": 5,
            "x_publik": 0, "y_gateway": 1, "y_update": 2, "y_legacy": 5, "mosca_source": ""}


def test_settings_weights_must_sum_to_one(client):
    assert client.put("/api/settings", json={**SETTINGS, "wA": 0.9}).status_code == 422
    good = {**SETTINGS, "wA": 0.25, "wS": 0.25, "wE": 0.25, "wM": 0.25, "quantum_year": 2035}
    assert client.put("/api/settings", json=good).json()["quantum_year"] == 2035


@pytest.mark.parametrize("change", [{"x_rahasia": -1}, {"y_legacy": 101}, {"x_internal": 1.5}, {"mosca_source": "x" * 201}])
def test_invalid_x_y_values_are_refused(client, change):
    assert client.put("/api/settings", json={**SETTINGS, **change}).status_code == 422


def test_defaults_apply_to_a_database_saved_before_x_y_existed(client):
    from qshield import db
    db.save_settings({"wA": 0.4, "wS": 0.3, "wE": 0.2, "wM": 0.1, "quantum_year": 2030})
    assert client.get("/api/dashboard").json()["settings"]["x_rahasia"] == 10


def test_new_x_y_apply_on_next_scan_and_source_reaches_the_report(client, tmp_path):
    scanned_repo(client, tmp_path)
    before = client.get("/api/dashboard").json()["rows"][0]["assessment"]
    assert before["mosca_vulnerable"] is True
    source = "Rekomendasi panitia <webinar & 2>"
    assert client.put("/api/settings", json={**SETTINGS, "x_internal": 1, "y_update": 1, "mosca_source": source}).status_code == 200
    assert client.get("/api/dashboard").json()["rows"][0]["assessment"]["mosca_vulnerable"] is True
    client.post("/api/scans")
    data = client.get("/api/dashboard").json()
    after = data["rows"][0]["assessment"]
    assert (after["X"], after["Y"], after["mosca_vulnerable"]) == (1, 1, False)
    assert after["risk"] == before["risk"]
    assert data["settings"]["mosca_source"] == source
    assert client.get("/api/report.pdf").content.startswith(b"%PDF-")


def scanned_repo(client, tmp_path):
    (tmp_path / "app.py").write_text("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    client.post("/api/targets", json=repo_target(tmp_path))
    assert client.post("/api/scans").status_code == 201


def test_scan_fills_dashboard(client, tmp_path):
    scanned_repo(client, tmp_path)
    data = client.get("/api/dashboard").json()
    assert data["rows"][0]["assessment"]["A"] == 1.0
    assert data["readiness"] is not None
    assert data["kpi"]["mosca_vulnerable"] == 1
    assert data["roadmap"][0]["target"] == "repo"


def test_cbom_validates_against_the_cyclonedx_1_6_schema(client, tmp_path):
    scanned_repo(client, tmp_path)
    document = client.get("/api/cbom").json()
    assert document["components"][0]["evidence"]["occurrences"][0] == {"location": "app.py", "line": 1}
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document)) is None


def test_cbom_with_certificate_validates(monkeypatch, client):
    certificate = {"subject": "CN=lab", "issuer": "CN=lab", "not_before": "2026-01-01T00:00:00+00:00",
                   "not_after": "2027-01-01T00:00:00+00:00"}
    item = {"algorithm": "X25519MLKEM768", "primitive": "kem", "role": "kex", "quantum": "safe", "nist_level": 3,
            "param": "X25519MLKEM768", "location": "portal:443"}
    from qshield import cbom
    document = cbom.build_cbom([{"target_id": 1, "target_name": "portal", "items": [item], "detail": {"certificate": certificate}}])
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document)) is None


def test_report_handles_hostile_scanned_text(client, tmp_path):
    client.post("/api/targets", json=repo_target(tmp_path, name="<b>bad & name</para>"))
    client.post("/api/scans")
    response = client.get("/api/report.pdf")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_report_works_before_any_scan(client):
    assert client.get("/api/report.pdf").content.startswith(b"%PDF-")


def test_seed_is_idempotent(client, tmp_path, monkeypatch):
    (tmp_path / "repo").mkdir()
    seed = tmp_path / "seed.json"
    entry = repo_target(tmp_path / "repo")
    del entry["authorized"]
    seed.write_text(json.dumps([entry]))
    monkeypatch.setenv("QSHIELD_SEED", str(seed))
    service.seed_targets()
    service.seed_targets()
    assert len(client.get("/api/dashboard").json()["targets"]) == 1


def test_security_headers_and_dashboard_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["content-security-policy"]


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_interactive_docs_are_disabled(client, path):
    assert client.get(path).status_code == 404
