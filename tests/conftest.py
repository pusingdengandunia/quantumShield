import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QSHIELD_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("QSHIELD_REPO_ROOT", str(tmp_path))
    for name in ("QSHIELD_READ_ONLY", "QSHIELD_API_TOKEN", "QSHIELD_ALLOW_PUBLIC", "QSHIELD_SEED", "QSHIELD_GATEWAY_CONF"):
        monkeypatch.delenv(name, raising=False)
    from qshield.app import app

    with TestClient(app, headers={"X-QShield": "1"}) as test_client:
        yield test_client
