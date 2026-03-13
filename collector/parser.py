"""Cowrie JSON log parsing utilities."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

try:
    from .models import HoneypotEvent
except ImportError:  # pragma: no cover - supports `python collector/parser.py`
    from models import HoneypotEvent

LOGGER = logging.getLogger(__name__)

EVENT_TYPE_MAP = {
    "cowrie.login.success": "login_success",
    "cowrie.login.failed": "login_failed",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.closed": "session_closed",
}

EVENT_ID_KEYS = ("event_id", "event_uuid", "uuid", "id")


def _configure_logging() -> None:
    """Configure a basic logger when the module is executed directly."""
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO)


def _log_parse_error(message: str, **context: Any) -> None:
    """Emit a structured JSON log entry without sensitive payload data."""
    LOGGER.error(
        json.dumps(
            {
                "level": "error",
                "msg": message,
                "context": context,
            },
            sort_keys=True,
            default=str,
        )
    )


def _resolve_event_id(payload: dict[str, Any]) -> str:
    """Return a stable event identifier for the normalized event."""
    for key in EVENT_ID_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, payload_json))


def parse_line(line: str) -> HoneypotEvent | None:
    """Parse one Cowrie JSON log line into a normalized honeypot event."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as error:
        _log_parse_error(
            "Failed to decode Cowrie JSON line",
            error=str(error),
            line_length=len(line),
        )
        return None

    if not isinstance(payload, dict):
        _log_parse_error(
            "Cowrie JSON line did not decode to an object",
            payload_type=type(payload).__name__,
        )
        return None

    eventid = payload.get("eventid")
    if not isinstance(eventid, str):
        _log_parse_error(
            "Cowrie event missing eventid",
            available_keys=sorted(payload.keys()),
        )
        return None

    event_type = EVENT_TYPE_MAP.get(eventid)
    if event_type is None:
        return None

    try:
        command = payload.get("input")
        if not isinstance(command, str):
            command = payload.get("command") if isinstance(payload.get("command"), str) else None

        event = HoneypotEvent(
            event_id=_resolve_event_id(payload),
            timestamp=payload["timestamp"],
            src_ip=payload["src_ip"],
            event_type=event_type,
            session_id=payload.get("session") or payload["session_id"],
            username=payload.get("username"),
            password=payload.get("password"),
            command=command,
            raw_payload=payload,
        )
    except (KeyError, TypeError, ValidationError) as error:
        _log_parse_error(
            "Failed to normalize Cowrie event",
            error=str(error),
            eventid=eventid,
            session=payload.get("session") or payload.get("session_id"),
        )
        return None

    return event


def parse_log_file(filepath: str) -> list[HoneypotEvent]:
    """Read a Cowrie JSON log file and return all supported parsed events."""
    events: list[HoneypotEvent] = []

    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            for line in handle:
                event = parse_line(line)
                if event is not None:
                    events.append(event)
    except OSError as error:
        _log_parse_error(
            "Failed to read Cowrie log file",
            error=str(error),
            filepath=filepath,
        )
        raise

    return events


def tail_log_file(filepath: str, callback: Callable[[HoneypotEvent], None]) -> None:
    """Watch a Cowrie log file for appended lines and invoke a callback per event."""
    with open(filepath, "r", encoding="utf-8") as handle:
        handle.seek(0, os.SEEK_END)

        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.2)
                continue

            event = parse_line(line)
            if event is not None:
                callback(event)


def main(argv: list[str] | None = None) -> int:
    """Parse a Cowrie log file from the command line and print normalized events."""
    _configure_logging()

    parser = argparse.ArgumentParser(description="Parse Cowrie JSON log files.")
    parser.add_argument("filepath", help="Path to a Cowrie JSON log file")
    args = parser.parse_args(argv)

    try:
        events = parse_log_file(args.filepath)
    except OSError:
        return 1

    for event in events:
        print(json.dumps(event.model_dump(mode="json"), sort_keys=True))

    return 0


if __name__ == "__main__":
    sys.exit(main())
