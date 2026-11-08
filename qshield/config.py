"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from pathlib import Path


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def db_path() -> Path:
    return Path(os.environ.get("QSHIELD_DB", "data/qshield.db"))


def read_only() -> bool:
    """Public demo mode: serve stored results, refuse every write and scan."""
    return _flag("QSHIELD_READ_ONLY")


def allow_public_targets() -> bool:
    """Scanning non-private addresses needs an explicit opt-in."""
    return _flag("QSHIELD_ALLOW_PUBLIC")


def repo_root() -> Path | None:
    """Only folders below this root can be registered as code targets."""
    value = os.environ.get("QSHIELD_REPO_ROOT")
    return Path(value).resolve() if value else None


def gateway_conf_dir() -> Path | None:
    value = os.environ.get("QSHIELD_GATEWAY_CONF")
    return Path(value) if value else None


def gateway_host() -> str:
    return os.environ.get("QSHIELD_GATEWAY_HOST", "gateway")


def gateway_ports() -> range:
    start = int(os.environ.get("QSHIELD_GATEWAY_PORT_START", "9443"))
    return range(start, start + 10)


def openssl_bin() -> str:
    return os.environ.get("QSHIELD_OPENSSL", "openssl")


def ca_bundle() -> Path:
    return Path(os.environ.get("QSHIELD_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"))


def extra_ca() -> Path | None:
    """Internal CA certificates to trust on top of the public bundle."""
    value = os.environ.get("QSHIELD_EXTRA_CA")
    return Path(value) if value else None


def seed_file() -> Path | None:
    value = os.environ.get("QSHIELD_SEED")
    return Path(value) if value else None
