"""End-to-end proof against the running lab. Needs `docker compose up -d --build`.

Run: python tests/e2e_lab.py
"""
import json
import sys
import time

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE, headers={"X-QShield": "1"}, timeout=240)


def wait_until_up():
    for _ in range(60):
        try:
            if client.get("/api/dashboard").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise SystemExit(f"Dashboard tidak aktif di {BASE}")


def scan() -> dict:
    assert client.post("/api/scans").status_code == 201
    return client.get("/api/dashboard").json()


def row(data: dict, name: str) -> dict:
    return next(r for r in data["rows"] if r["target_name"] == name)


def kex(result: dict) -> str:
    return next(item["algorithm"] for item in result["items"] if item["role"] == "kex")


wait_until_up()
targets = {t["name"]: t["id"] for t in client.get("/api/dashboard").json()["targets"]}
portal_id = targets["Portal Internal"]
client.delete(f"/api/targets/{portal_id}/gateway")
time.sleep(2)

before = scan()
assert kex(row(before, "Portal Internal")) == "X25519"
portal = row(before, "Portal Internal")
assert portal["assessment"]["risk"] == 86.0
assert portal["priority"] == "P1" and portal["status"] == "high"
assert portal["detail"]["pki"]["trust"]["verified"] is True, portal["detail"]["pki"]["trust"]
assert [c["role"] for c in portal["detail"]["pki"]["chain"]] == ["leaf", "intermediate"]

ready = row(before, "Layanan PQ-Ready")
assert kex(ready) == "X25519MLKEM768"
assert (ready["assessment"]["risk"], ready["status"]) == (18.8, "partial"), ready["assessment"]
assert ready["detail"]["pki"]["auth_status"] == "classic"

full = row(before, "Layanan PQ-Full")
audit = full["detail"]["pki"]
assert audit["auth_status"] == "pqc", audit
assert audit["negotiated_signature"] == "mldsa65"
assert audit["trust"] == {"verified": True, "code": "0 (ok)", "hostname_match": True}
assert (full["assessment"]["risk"], full["status"], full["priority"]) == (0.0, "protected", "P4"), full["assessment"]
assert before["kpi"]["pqc_auth"] == 1

legacy = row(before, "API Logistik Lama")
assert legacy["detail"]["versions"] == ["TLSv1.2"]
assert legacy["detail"]["pki"]["chain"][0]["key_size"] == 1024
assert legacy["detail"]["pki"]["trust"]["verified"] is False
assert row(before, "Server Admin SSH")["detail"]["hybrid"] is False
repo = row(before, "Repo Aplikasi Satuan")
assert any(item["location"] == "keys/dummy_rsa.pem" for item in repo["items"])
assert [r["priority"] for r in before["rows"]] == sorted(r["priority"] for r in before["rows"])
print(f"sebelum gateway: skor {before['readiness']}")

found = client.post("/api/servers/discover", json={"host": "https://portal/", "authorized": True}).json()
assert {(s["port"], s["kind"]) for s in found["services"]} == {(443, "tls"), (8443, "tls")}, found
assert next(s for s in found["services"] if s["port"] == 443)["registered"] is True
found = client.post("/api/servers/discover", json={"host": "ssh-admin", "authorized": True}).json()
assert [(s["port"], s["kind"]) for s in found["services"]] == [(22, "ssh")], found
print("deteksi server: ok")

assert client.post(f"/api/targets/{targets['API Logistik Lama']}/gateway").status_code == 400

applied = client.post(f"/api/targets/{portal_id}/gateway").json()
assert applied["status"] == "aktif", applied
after = scan()
assert kex(row(after, "Portal Internal")) == "X25519MLKEM768"
protected = row(after, "Portal Internal")
assert (protected["assessment"]["risk"], protected["status"]) == (25.8, "partial"), protected["assessment"]
assert {d["code"] for d in protected["assessment"]["drivers"]} == {"direct_open", "auth_classic"}
assert protected["detail"]["pki"]["trust"]["verified"] is True
assert after["readiness"] > before["readiness"]
print(f"sesudah gateway: skor {after['readiness']} (port {applied['port']})")

bench = client.post(f"/api/targets/{portal_id}/benchmark").json()
assert bench["extra_bytes"] > 0
print(f"benchmark: +{bench['extra_bytes']} byte, {bench['extra_ms']:+} ms per handshake")

cbom = client.get("/api/cbom").json()
assert cbom["specVersion"] == "1.6" and cbom["components"]
assert client.get("/api/report.pdf").content.startswith(b"%PDF-")
print(f"cbom: {len(cbom['components'])} komponen; pdf: ok")
print("E2E LULUS")
print(json.dumps({"before": before["readiness"], "after": after["readiness"], "benchmark": bench}))
