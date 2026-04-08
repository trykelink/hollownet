"""Tests for Cowrie event parsing."""

from __future__ import annotations

import json
import logging

import pytest

from collector.app.parser import parse_event, parse_log_line, parse_log_lines, parse_timestamp


def test_parse_timestamp_returns_utc_datetime() -> None:
    parsed = parse_timestamp("2026-04-08T12:30:45.000000Z")

    assert parsed.isoformat() == "2026-04-08T12:30:45+00:00"


def test_parse_event_normalizes_supported_payload() -> None:
    payload = {
        "eventid": "cowrie.command.input",
        "uuid": "event-123",
        "session": "session-123",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-04-08T12:30:45.000000Z",
        "username": "root",
        "password": "admin",
        "input": "whoami",
        "protocol": "ssh",
    }

    parsed_event = parse_event(payload)

    assert parsed_event is not None
    assert parsed_event.event_id == "event-123"
    assert parsed_event.command == "whoami"
    assert parsed_event.protocol == "ssh"
    assert parsed_event.raw["eventid"] == "cowrie.command.input"


def test_parse_event_returns_none_for_unsupported_event() -> None:
    payload = {
        "eventid": "cowrie.file.upload",
        "session": "session-1",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-04-08T12:30:45.000000Z",
    }

    assert parse_event(payload) is None


def test_parse_log_line_returns_none_for_invalid_json() -> None:
    assert parse_log_line("{not-json}") is None


def test_parse_event_returns_none_and_warns_when_required_fields_missing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = {
        "eventid": "cowrie.login.failed",
        "session": "session-x",
        # src_ip and timestamp are intentionally absent
    }

    with caplog.at_level(logging.WARNING, logger="collector.app.parser"):
        result = parse_event(payload)

    assert result is None
    assert any("missing required fields" in record.message for record in caplog.records)


def test_parse_log_lines_generate_stable_hash_ids_without_uuid() -> None:
    payload = {
        "eventid": "cowrie.login.failed",
        "session": "session-2",
        "src_ip": "198.51.100.20",
        "timestamp": "2026-04-08T13:00:00.000000Z",
        "username": "root",
        "password": "guest",
    }
    lines = [json.dumps(payload), json.dumps(payload)]

    parsed_events = parse_log_lines(lines)

    assert len(parsed_events) == 2
    assert parsed_events[0].event_id == parsed_events[1].event_id
