"""FastAPI collector API for event ingestion and dashboard read endpoints."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
from time import perf_counter
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from collector import dynamo, enricher
from collector.models import (
    EnrichedEvent,
    ErrorResponse,
    EventType,
    HealthResponse,
    HoneypotEvent,
    IPEnrichment,
    StatsResponse,
)

load_dotenv(Path(__file__).with_name(".env"))

logger = logging.getLogger(__name__)

_DEFAULT_COWRIE_PID_PATH = "/home/cowrie/cowrie/var/run/cowrie.pid"


class PersistenceError(RuntimeError):
    """Raised when event persistence fails."""


def _is_private_ip(ip: str) -> bool:
    """Return True when *ip* is private/loopback/link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _merge_event_with_enrichment(event: HoneypotEvent, enrichment: IPEnrichment) -> EnrichedEvent:
    merged = event.model_dump()
    merged.update(
        {
            "country": enrichment.country,
            "country_code": enrichment.country_code,
            "city": enrichment.city,
            "lat": enrichment.lat,
            "lon": enrichment.lon,
            "isp": enrichment.isp,
            "abuse_score": enrichment.abuse_score,
            "total_reports": enrichment.total_reports,
        }
    )
    return EnrichedEvent(**merged)


def _process_event(event: HoneypotEvent, *, dynamo_client: Any) -> EnrichedEvent:
    if _is_private_ip(event.src_ip):
        enrichment = IPEnrichment(
            ip=event.src_ip,
            cached_at=datetime.now(timezone.utc).isoformat(),
        )
    else:
        enrichment = enricher.enrich_ip(event.src_ip, dynamo_client=dynamo_client)

    enriched_event = _merge_event_with_enrichment(event, enrichment)
    try:
        dynamo.put_event(enriched_event, client=dynamo_client)
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "Failed to persist event",
                    "context": {"event_id": event.event_id, "error": str(exc)},
                }
            )
        )
        raise PersistenceError("Failed to persist event to DynamoDB") from exc
    return enriched_event


def _health_status() -> HealthResponse:
    pid_path = Path(os.environ.get("COWRIE_PID_PATH", _DEFAULT_COWRIE_PID_PATH))
    if pid_path.exists():
        return HealthResponse(status="ok", cowrie="running")
    return HealthResponse(status="degraded", cowrie="stopped")


def _error_payload(error: str, detail: str) -> dict[str, str]:
    return ErrorResponse(error=error, detail=detail).model_dump()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        json.dumps(
            {
                "level": "info",
                "msg": "Collector API startup",
                "context": {"service": "collector-api"},
            }
        )
    )
    app.state.dynamo_client = None
    yield
    logger.info(
        json.dumps(
            {
                "level": "info",
                "msg": "Collector API shutdown",
                "context": {"service": "collector-api"},
            }
        )
    )


app = FastAPI(title="Hollownet Collector API", version="1.0.0", lifespan=lifespan)

allowed_origins = {
    "http://localhost:3000",
    os.environ.get("DASHBOARD_URL", "http://localhost:3000"),
}
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin for origin in allowed_origins if origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start = perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = round((perf_counter() - start) * 1000, 2)
        logger.info(
            json.dumps(
                {
                    "level": "info",
                    "msg": "request_complete",
                    "context": {
                        "method": request.method,
                        "path": request.url.path,
                        "status": status_code,
                        "duration_ms": duration_ms,
                    },
                }
            )
        )


def get_dynamo_client(request: Request) -> Any:
    """Return a shared DynamoDB client from app state."""
    client = getattr(request.app.state, "dynamo_client", None)
    if client is None:
        client = dynamo.create_dynamo_client()
        request.app.state.dynamo_client = client
    return client


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and {"error", "detail"}.issubset(exc.detail):
        payload = exc.detail
    else:
        payload = _error_payload("http_error", str(exc.detail))
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    payload = _error_payload("validation_error", "Request validation failed")
    return JSONResponse(status_code=422, content=payload)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.error(
        json.dumps(
            {
                "level": "error",
                "msg": "Unhandled exception in Collector API",
                "context": {"error": str(exc)},
            }
        )
    )
    payload = _error_payload("internal_error", "Unexpected server error")
    return JSONResponse(status_code=500, content=payload)


@app.post(
    "/events",
    response_model=EnrichedEvent,
    responses={503: {"model": ErrorResponse}},
)
def create_event(event: HoneypotEvent, dynamo_client: Any = Depends(get_dynamo_client)) -> EnrichedEvent:
    try:
        return _process_event(event, dynamo_client=dynamo_client)
    except EnvironmentError as exc:
        raise HTTPException(
            status_code=503,
            detail=_error_payload("service_unavailable", str(exc)),
        ) from exc
    except PersistenceError as exc:
        raise HTTPException(
            status_code=503,
            detail=_error_payload("service_unavailable", str(exc)),
        ) from exc


@app.get(
    "/events",
    response_model=list[EnrichedEvent],
    responses={503: {"model": ErrorResponse}},
)
def list_events(
    src_ip: str | None = Query(default=None),
    event_type: EventType | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    dynamo_client: Any = Depends(get_dynamo_client),
) -> list[EnrichedEvent]:
    try:
        return dynamo.get_events(
            src_ip=src_ip,
            event_type=event_type,
            limit=limit,
            client=dynamo_client,
        )
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "Failed to fetch events",
                    "context": {
                        "src_ip": src_ip,
                        "event_type": event_type,
                        "limit": limit,
                        "error": str(exc),
                    },
                }
            )
        )
        raise HTTPException(
            status_code=503,
            detail=_error_payload("service_unavailable", f"DynamoDB query failed: {exc}"),
        ) from exc


@app.get(
    "/stats",
    response_model=StatsResponse,
    responses={503: {"model": ErrorResponse}},
)
def get_stats(dynamo_client: Any = Depends(get_dynamo_client)) -> StatsResponse:
    try:
        return dynamo.get_stats(client=dynamo_client)
    except Exception as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "Failed to fetch stats",
                    "context": {"error": str(exc)},
                }
            )
        )
        raise HTTPException(
            status_code=503,
            detail=_error_payload("service_unavailable", f"DynamoDB query failed: {exc}"),
        ) from exc


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return _health_status()
