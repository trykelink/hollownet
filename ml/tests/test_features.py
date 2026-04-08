"""Tests for ML feature extraction."""

from __future__ import annotations

from datetime import datetime, timezone

from ml.features import extract_features


def test_extract_features_returns_expected_columns() -> None:
    events = [
        {
            "event_id": "event-1",
            "session": "session-1",
            "src_ip": "203.0.113.10",
            "timestamp": datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc),
            "username": "root",
            "password": "admin",
            "command": None,
            "eventid": "cowrie.login.failed",
        },
        {
            "event_id": "event-2",
            "session": "session-1",
            "src_ip": "203.0.113.10",
            "timestamp": datetime(2026, 4, 6, 12, 30, tzinfo=timezone.utc),
            "username": "root",
            "password": "guest",
            "command": "whoami",
            "eventid": "cowrie.command.input",
        },
    ]

    features = extract_features(events)

    assert list(features.columns) == [
        "hour_of_day",
        "is_weekend",
        "session_duration",
        "attempts_per_ip",
        "unique_passwords",
        "unique_usernames",
        "has_command",
        "is_login_success",
    ]
    assert list(features.index) == ["event-1", "event-2"]
    assert features.loc["event-2", "session_duration"] == 1800.0
    assert features.loc["event-2", "attempts_per_ip"] == 2


def test_extract_features_marks_weekend_events() -> None:
    events = [
        {
            "event_id": "weekend-event",
            "session": "weekend-session",
            "src_ip": "203.0.113.11",
            "timestamp": datetime(2026, 4, 11, 9, 0, tzinfo=timezone.utc),
            "username": "root",
            "password": "admin",
            "command": None,
            "eventid": "cowrie.login.failed",
        }
    ]

    features = extract_features(events)

    assert features.loc["weekend-event", "is_weekend"] == 1


def test_extract_features_marks_events_with_commands() -> None:
    events = [
        {
            "event_id": "command-event",
            "session": "command-session",
            "src_ip": "203.0.113.12",
            "timestamp": datetime(2026, 4, 7, 15, 0, tzinfo=timezone.utc),
            "username": "root",
            "password": "admin",
            "command": "uname -a",
            "eventid": "cowrie.command.input",
        }
    ]

    features = extract_features(events)

    assert features.loc["command-event", "has_command"] == 1


def test_extract_features_handles_empty_input() -> None:
    features = extract_features([])

    assert features.empty
    assert list(features.columns) == [
        "hour_of_day",
        "is_weekend",
        "session_duration",
        "attempts_per_ip",
        "unique_passwords",
        "unique_usernames",
        "has_command",
        "is_login_success",
    ]
