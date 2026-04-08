"""Helpers for parsing and normalizing Cowrie JSON events."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

SUPPORTED_EVENT_IDS = {
    "cowrie.session.connect",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
    "cowrie.session.closed",
}


class ParsedEvent(BaseModel):
    """Normalized Cowrie event ready to persist in the database."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    session: str
    src_ip: str
    timestamp: datetime
    protocol: str
    username: str | None = None
    password: str | None = None
    command: str | None = None
    raw: dict[str, Any]


def parse_timestamp(value: str) -> datetime:
    """Parse a Cowrie timestamp into a timezone-aware UTC datetime."""

    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_supported_event(payload: Mapping[str, Any]) -> bool:
    """Return whether a Cowrie payload represents a supported event."""

    return str(payload.get("eventid", "")) in SUPPORTED_EVENT_IDS


def parse_event(payload: Mapping[str, Any]) -> ParsedEvent | None:
    """Normalize a single Cowrie payload into the collector schema."""

    if not is_supported_event(payload):
        return None

    required_fields = ("session", "src_ip", "timestamp")
    missing_fields = [field_name for field_name in required_fields if not payload.get(field_name)]
    if missing_fields:
        logger.warning("Skipping Cowrie event missing required fields: %s", ",".join(missing_fields))
        return None

    raw_payload = dict(payload)
    timestamp = parse_timestamp(str(raw_payload["timestamp"]))

    return ParsedEvent(
        event_id=_derive_event_id(raw_payload),
        session=str(raw_payload["session"]),
        src_ip=str(raw_payload["src_ip"]),
        timestamp=timestamp,
        protocol=_extract_protocol(raw_payload),
        username=_optional_string(raw_payload.get("username")),
        password=_optional_string(raw_payload.get("password")),
        command=_extract_command(raw_payload),
        raw=raw_payload,
    )


def parse_log_line(line: str) -> ParsedEvent | None:
    """Parse a single JSON log line from Cowrie."""

    stripped_line = line.strip()
    if not stripped_line:
        return None

    try:
        payload = json.loads(stripped_line)
    except json.JSONDecodeError:
        logger.warning("Skipping invalid Cowrie JSON line")
        return None

    if not isinstance(payload, dict):
        logger.warning("Skipping Cowrie log entry with non-object payload")
        return None

    return parse_event(payload)


def parse_log_lines(lines: Iterable[str]) -> list[ParsedEvent]:
    """Parse multiple Cowrie JSON log lines into normalized events."""

    parsed_events: list[ParsedEvent] = []
    for line in lines:
        parsed_event = parse_log_line(line)
        if parsed_event is not None:
            parsed_events.append(parsed_event)
    return parsed_events


def _derive_event_id(payload: Mapping[str, Any]) -> str:
    for candidate_key in ("uuid", "event_uuid", "event_id", "message_id"):
        candidate_value = payload.get(candidate_key)
        if candidate_value:
            return str(candidate_value)

    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def _extract_command(payload: Mapping[str, Any]) -> str | None:
    command_value = payload.get("input") or payload.get("command")
    return _optional_string(command_value)


def _extract_protocol(payload: Mapping[str, Any]) -> str:
    protocol_value = payload.get("protocol") or payload.get("transport")
    if protocol_value:
        return str(protocol_value)
    return "ssh"


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None

    stripped_value = str(value).strip()
    return stripped_value or None
