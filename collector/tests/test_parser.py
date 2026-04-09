"""Tests for Cowrie event parsing."""

from __future__ import annotations

import json
import hashlib
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
    assert parsed_event.raw["uuid"] == "event-123"


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


def test_parse_log_lines_generate_stable_hash_ids_from_raw_payload_without_uuid() -> None:
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
    assert parsed_events[0].event_id == hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def test_parse_event_generates_distinct_ids_for_same_timestamp_with_different_payloads() -> None:
    first_payload = {
        "eventid": "cowrie.command.input",
        "session": "shared-session",
        "src_ip": "198.51.100.42",
        "timestamp": "2026-04-08T13:00:00.000000Z",
        "input": "uname -a",
    }
    second_payload = {
        "eventid": "cowrie.command.input",
        "session": "shared-session",
        "src_ip": "198.51.100.42",
        "timestamp": "2026-04-08T13:00:00.000000Z",
        "input": "whoami",
    }

    first_event = parse_event(first_payload)
    second_event = parse_event(second_payload)

    assert first_event is not None
    assert second_event is not None
    assert first_event.event_id != second_event.event_id
