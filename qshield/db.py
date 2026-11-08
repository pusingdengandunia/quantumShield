"""SQLite persistence. Scan results are stored as JSON documents."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config
from .risk import DEFAULT_SETTINGS

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    path TEXT,
    sensitivity TEXT NOT NULL,
    exposure TEXT NOT NULL,
    migration TEXT NOT NULL,
    gateway_port INTEGER,
    gateway_status TEXT,
    created_at TEXT NOT NULL,
    server TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finished_at TEXT NOT NULL,
    readiness REAL
);
CREATE TABLE IF NOT EXISTS results (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL,
    target_name TEXT NOT NULL,
    document TEXT NOT NULL,
    PRIMARY KEY (scan_id, target_id)
);
CREATE TABLE IF NOT EXISTS benchmarks (
    target_id INTEGER PRIMARY KEY,
    measured_at TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    document TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    path = config.db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init() -> None:
    with connect() as db:
        db.executescript(_SCHEMA)
        # Databases created before server grouping lack the column.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(targets)")}
        if "server" not in columns:
            db.execute("ALTER TABLE targets ADD COLUMN server TEXT")


def get_settings() -> dict:
    with connect() as db:
        row = db.execute("SELECT document FROM settings WHERE id = 1").fetchone()
    return {**DEFAULT_SETTINGS, **json.loads(row["document"])} if row else dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    with connect() as db:
        db.execute("INSERT INTO settings (id, document) VALUES (1, ?) "
                   "ON CONFLICT(id) DO UPDATE SET document = excluded.document", (json.dumps(settings),))


def list_targets() -> list[dict]:
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM targets ORDER BY id")]


def get_target(target_id: int) -> dict | None:
    with connect() as db:
        row = db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return dict(row) if row else None


def add_target(values: dict) -> int:
    with connect() as db:
        cursor = db.execute(
            "INSERT INTO targets (name, kind, host, port, path, sensitivity, exposure, migration, server, created_at) "
            "VALUES (:name, :kind, :host, :port, :path, :sensitivity, :exposure, :migration, :server, :created_at)",
            {**values, "created_at": now()})
        return cursor.lastrowid


def delete_target(target_id: int) -> None:
    with connect() as db:
        db.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        db.execute("DELETE FROM benchmarks WHERE target_id = ?", (target_id,))


def set_gateway(target_id: int, port: int | None, status: str | None) -> None:
    with connect() as db:
        db.execute("UPDATE targets SET gateway_port = ?, gateway_status = ? WHERE id = ?", (port, status, target_id))


def save_scan(results: list[dict], readiness: float | None) -> int:
    with connect() as db:
        scan_id = db.execute("INSERT INTO scans (finished_at, readiness) VALUES (?, ?)", (now(), readiness)).lastrowid
        for result in results:
            db.execute("INSERT INTO results (scan_id, target_id, target_name, document) VALUES (?, ?, ?, ?)",
                       (scan_id, result["target_id"], result["target_name"], json.dumps(result)))
        return scan_id


def scan_history(limit: int = 30) -> list[dict]:
    with connect() as db:
        rows = db.execute("SELECT id, finished_at, readiness FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in reversed(rows)]


def latest_results() -> list[dict]:
    with connect() as db:
        rows = db.execute("SELECT document FROM results WHERE scan_id = (SELECT MAX(id) FROM scans)").fetchall()
    return [json.loads(row["document"]) for row in rows]


def save_benchmark(target_id: int, document: dict) -> None:
    with connect() as db:
        db.execute("INSERT INTO benchmarks (target_id, measured_at, document) VALUES (?, ?, ?) "
                   "ON CONFLICT(target_id) DO UPDATE SET measured_at = excluded.measured_at, document = excluded.document",
                   (target_id, now(), json.dumps(document)))


def list_benchmarks() -> dict[int, dict]:
    with connect() as db:
        rows = db.execute("SELECT target_id, measured_at, document FROM benchmarks").fetchall()
    return {row["target_id"]: {**json.loads(row["document"]), "measured_at": row["measured_at"]} for row in rows}
