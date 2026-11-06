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
assert row(before, "Portal Internal")["assessment"]["risk"] == 86.0
assert kex(row(before, "Layanan PQ-Ready")) == "X25519MLKEM768"
assert row(before, "Layanan PQ-Ready")["assessment"]["risk"] == 0
legacy = row(before, "API Logistik Lama")
assert legacy["detail"]["versions"] == ["TLSv1.2"]
assert legacy["detail"]["certificate"]["size"] == 1024
assert row(before, "Server Admin SSH")["detail"]["hybrid"] is False
repo = row(before, "Repo Aplikasi Satuan")
assert any(item["location"] == "keys/dummy_rsa.pem" for item in repo["items"])
print(f"sebelum gateway: skor {before['readiness']}")

assert client.post(f"/api/targets/{targets['API Logistik Lama']}/gateway").status_code == 400

applied = client.post(f"/api/targets/{portal_id}/gateway").json()
assert applied["status"] == "aktif", applied
after = scan()
assert kex(row(after, "Portal Internal")) == "X25519MLKEM768"
assert row(after, "Portal Internal")["assessment"]["risk"] == 0
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
