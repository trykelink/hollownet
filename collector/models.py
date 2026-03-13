"""Pydantic models for normalized honeypot events and API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, field_validator

EventType = Literal[
    "login_success",
    "login_failed",
    "command",
    "file_download",
    "session_closed",
]


class HoneypotEvent(BaseModel):
    """Normalized Cowrie event ready for collector ingestion."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: str
    src_ip: str
    event_type: EventType
    session_id: str
    username: str | None = None
    password: str | None = None
    command: str | None = None
    raw_payload: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        """Ensure timestamps are ISO8601 strings."""
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value


class IPEnrichment(BaseModel):
    """Geolocation and reputation data for a source IP, cached in DynamoDB."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    abuse_score: int = 0
    total_reports: int = 0
    cached_at: str  # ISO8601


class EnrichedEvent(HoneypotEvent):
    """Honeypot event augmented with IP enrichment fields."""

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    abuse_score: int = 0
    total_reports: int = 0


class ErrorResponse(BaseModel):
    """Consistent API error envelope."""

    model_config = ConfigDict(extra="forbid")

    error: str
    detail: str


class HealthResponse(BaseModel):
    """Collector health endpoint response."""

    model_config = ConfigDict(extra="forbid")

    status: str
    cowrie: str


class TopIP(BaseModel):
    """Top source IP aggregate."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    count: int
    country: Optional[str] = None
    abuse_score: int = 0


class TopCredential(BaseModel):
    """Top attempted credential tuple aggregate."""

    model_config = ConfigDict(extra="forbid")

    username: str
    password: str
    count: int


class StatsResponse(BaseModel):
    """Collector dashboard aggregate response."""

    model_config = ConfigDict(extra="forbid")

    total_events: int
    events_today: int
    top_ips: list[TopIP]
    top_credentials: list[TopCredential]
    events_by_type: dict[str, int]
