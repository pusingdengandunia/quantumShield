"""FastAPI application: REST API plus the static dashboard."""
from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from . import __version__, cbom, config, db, gateway, report, service

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    if not config.read_only():
        service.seed_targets()
    yield


app = FastAPI(title="Kartika Q-Shield", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def require_write(x_qshield: str | None = Header(default=None), x_qshield_token: str | None = Header(default=None)):
    """Writes need a custom header, which cross-site pages cannot send without CORS."""
    if config.read_only():
        raise HTTPException(403, "Mode demo baca-saja: scan dan perubahan dinonaktifkan.")
    if x_qshield != "1":
        raise HTTPException(403, "Header X-QShield wajib ada.")
    token = os.environ.get("QSHIELD_API_TOKEN")
    if token and not secrets.compare_digest(token, x_qshield_token or ""):
        raise HTTPException(401, "Token API salah.")


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["tls", "ssh", "repo"]
    host: str | None = None
    port: int | None = None
    path: str | None = None
    sensitivity: Literal["rahasia", "internal", "publik"]
    exposure: Literal["internet", "antar-satuan", "lan"]
    migration: Literal["gateway", "update", "legacy"]
    authorized: bool = False

    @model_validator(mode="after")
    def must_be_authorized(self):
        if not self.authorized:
            raise ValueError("Konfirmasi izin scan wajib dicentang.")
        return self


class DiscoverIn(BaseModel):
    host: str = Field(min_length=1, max_length=2048)
    authorized: bool = False

    @model_validator(mode="after")
    def must_be_authorized(self):
        if not self.authorized:
            raise ValueError("Konfirmasi izin scan wajib dicentang.")
        return self


class ServiceIn(BaseModel):
    port: int
    kind: Literal["tls", "ssh"]


class ServerIn(DiscoverIn):
    services: list[ServiceIn] = Field(min_length=1, max_length=10)
    sensitivity: Literal["rahasia", "internal", "publik"]
    exposure: Literal["internet", "antar-satuan", "lan"]
    migration: Literal["gateway", "update", "legacy"]


class SettingsIn(BaseModel):
    wA: float = Field(ge=0, le=1)
    wS: float = Field(ge=0, le=1)
    wE: float = Field(ge=0, le=1)
    wM: float = Field(ge=0, le=1)
    quantum_year: int = Field(ge=2026, le=2100)
    x_rahasia: int = Field(ge=0, le=100)
    x_internal: int = Field(ge=0, le=100)
    x_publik: int = Field(ge=0, le=100)
    y_gateway: int = Field(ge=0, le=100)
    y_update: int = Field(ge=0, le=100)
    y_legacy: int = Field(ge=0, le=100)
    mosca_source: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def weights_sum_to_one(self):
        if abs(self.wA + self.wS + self.wE + self.wM - 1) > 0.001:
            raise ValueError("Jumlah bobot harus 1.")
        return self


@app.exception_handler(service.TargetError)
async def target_error(_, error: service.TargetError):
    return JSONResponse({"detail": str(error)}, status_code=400)


@app.exception_handler(gateway.GatewayError)
async def gateway_error(_, error: gateway.GatewayError):
    return JSONResponse({"detail": str(error)}, status_code=409)


@app.get("/api/dashboard")
def get_dashboard():
    return service.dashboard()


@app.post("/api/targets", status_code=201, dependencies=[Depends(require_write)])
def create_target(body: TargetIn):
    return {"id": service.register_target(body.model_dump(exclude={"authorized"}))}


@app.delete("/api/targets/{target_id}", status_code=204, dependencies=[Depends(require_write)])
def remove_target(target_id: int):
    service.remove_gateway(target_id)
    db.delete_target(target_id)


@app.post("/api/servers/discover", dependencies=[Depends(require_write)])
def discover_server(body: DiscoverIn):
    return service.discover_services(body.host)


@app.post("/api/servers", status_code=201, dependencies=[Depends(require_write)])
def create_server(body: ServerIn):
    services = [item.model_dump() for item in body.services]
    return {"ids": service.register_server(body.host, services, body.sensitivity, body.exposure, body.migration)}


@app.post("/api/scans", status_code=201, dependencies=[Depends(require_write)])
def create_scan():
    return {"scan_id": service.run_scan()}


@app.get("/api/scans/progress")
def get_scan_progress():
    return service.scan_progress()


@app.post("/api/targets/{target_id}/gateway", dependencies=[Depends(require_write)])
def apply_gateway(target_id: int):
    return service.apply_gateway(target_id)


@app.delete("/api/targets/{target_id}/gateway", status_code=204, dependencies=[Depends(require_write)])
def remove_gateway(target_id: int):
    service.remove_gateway(target_id)


@app.post("/api/targets/{target_id}/benchmark", dependencies=[Depends(require_write)])
def benchmark(target_id: int):
    return service.run_benchmark(target_id)


@app.put("/api/settings", dependencies=[Depends(require_write)])
def put_settings(body: SettingsIn):
    db.save_settings(body.model_dump())
    return db.get_settings()


@app.get("/api/cbom")
def get_cbom():
    return JSONResponse(cbom.build_cbom(db.latest_results()),
                        headers={"Content-Disposition": 'attachment; filename="qshield-cbom.cdx.json"'})


@app.get("/api/report.pdf")
def get_report():
    return Response(report.build_pdf(service.dashboard()), media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="qshield-laporan.pdf"'})


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
