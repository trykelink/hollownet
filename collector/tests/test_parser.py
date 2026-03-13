"""Unit tests for the Cowrie parser."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.parser import parse_line, parse_log_file


@pytest.fixture
def cowrie_samples() -> dict[str, dict[str, str]]:
    """Provide representative Cowrie payloads for all supported event types."""
    return {
        "login_success": {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-03-13T12:00:00.000000Z",
            "src_ip": "203.0.113.10",
            "session": "abc123",
            "username": "root",
            "password": "toor",
            "event_id": "evt-login-success",
        },
        "login_failed": {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-03-13T12:01:00.000000Z",
            "src_ip": "203.0.113.11",
            "session": "abc124",
            "username": "admin",
            "password": "123456",
            "event_id": "evt-login-failed",
        },
        "command": {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-03-13T12:02:00.000000Z",
            "src_ip": "203.0.113.12",
            "session": "abc125",
            "username": "root",
            "input": "uname -a",
            "event_id": "evt-command",
        },
        "file_download": {
            "eventid": "cowrie.session.file_download",
            "timestamp": "2026-03-13T12:03:00.000000Z",
            "src_ip": "203.0.113.13",
            "session": "abc126",
            "username": "root",
            "url": "http://malicious.example/payload.sh",
            "event_id": "evt-file-download",
        },
        "session_closed": {
            "eventid": "cowrie.session.closed",
            "timestamp": "2026-03-13T12:04:00.000000Z",
            "src_ip": "203.0.113.14",
            "session": "abc127",
            "username": "root",
            "duration": 12.5,
            "event_id": "evt-session-closed",
        },
    }


@pytest.fixture
def unknown_sample() -> dict[str, str]:
    """Provide an unsupported Cowrie event payload."""
    return {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-03-13T12:05:00.000000Z",
        "src_ip": "203.0.113.15",
        "session": "abc128",
    }


@pytest.fixture
def malformed_line() -> str:
    """Provide malformed JSON content."""
    return '{"eventid": "cowrie.login.success",'


@pytest.fixture
def log_fixture(cowrie_samples: dict[str, dict[str, str]], unknown_sample: dict[str, str], malformed_line: str) -> str:
    """Provide mixed multi-line log content for file parsing tests."""
    lines = [
        json.dumps(cowrie_samples["login_success"]),
        json.dumps(cowrie_samples["command"]),
        json.dumps(unknown_sample),
        malformed_line,
        json.dumps(cowrie_samples["session_closed"]),
    ]
    return "\n".join(lines)


def test_parse_line_valid_events(cowrie_samples: dict[str, dict[str, str]]) -> None:
    """parse_line should normalize each supported Cowrie event type."""
    for expected_event_type, payload in cowrie_samples.items():
        event = parse_line(json.dumps(payload))

        assert event is not None
        assert event.event_type == expected_event_type
        assert event.event_id == payload["event_id"]
        assert event.src_ip == payload["src_ip"]
        assert event.session_id == payload["session"]


def test_parse_line_unknown_eventid_returns_none(unknown_sample: dict[str, str]) -> None:
    """parse_line should skip unsupported Cowrie event types."""
    assert parse_line(json.dumps(unknown_sample)) is None


def test_parse_line_handles_malformed_json_gracefully(malformed_line: str, caplog: pytest.LogCaptureFixture) -> None:
    """parse_line should return None and emit structured logs for invalid JSON."""
    with caplog.at_level("ERROR"):
        event = parse_line(malformed_line)

    assert event is None
    assert caplog.records

    log_payload = json.loads(caplog.records[-1].message)
    assert log_payload["msg"] == "Failed to decode Cowrie JSON line"
    assert log_payload["context"]["line_length"] == len(malformed_line)


def test_parse_log_file_counts_supported_events(log_fixture: str) -> None:
    """parse_log_file should return only the supported events from a log stream."""
    mocked_open = mock_open(read_data=log_fixture)

    with patch("collector.parser.open", mocked_open):
        events = parse_log_file("/tmp/cowrie.json")

    assert len(events) == 3
    assert [event.event_type for event in events] == [
        "login_success",
        "command",
        "session_closed",
    ]
