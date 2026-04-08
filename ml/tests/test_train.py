"""Tests for the ML training entrypoint."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import ANY, Mock

import pandas as pd
import pytest

from ml import train


def _build_events(count: int) -> list[dict]:
    return [
        {
            "event_id": f"event-{index}",
            "session": f"session-{index // 2}",
            "src_ip": f"203.0.113.{(index % 5) + 1}",
            "timestamp": datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc),
            "username": "root",
            "password": "admin",
            "command": None,
            "protocol": "ssh",
            "eventid": "cowrie.login.failed",
            "country": "AR",
        }
        for index in range(count)
    ]


def _build_connection_mock() -> Mock:
    conn = Mock()
    context_manager = Mock()
    context_manager.__enter__ = Mock(return_value=conn)
    context_manager.__exit__ = Mock(return_value=None)
    return context_manager


def test_main_runs_training_pipeline_for_sufficient_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _build_events(60)
    features = pd.DataFrame({"feature": [1.0] * 60}, index=[event["event_id"] for event in events])
    scores = pd.Series([90.0] * 60, index=features.index)
    detector = Mock()
    detector.score.return_value = scores
    detector_class = Mock(return_value=detector)
    send_daily_report = Mock()

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-id")
    monkeypatch.setattr(train.psycopg2, "connect", Mock(return_value=_build_connection_mock()))
    monkeypatch.setattr(train, "create_tables", Mock())
    monkeypatch.setattr(train, "get_events", Mock(return_value=events))
    monkeypatch.setattr(train, "extract_features", Mock(return_value=features))
    monkeypatch.setattr(train, "AnomalyDetector", detector_class)
    monkeypatch.setattr(train, "update_anomaly_scores", Mock())
    monkeypatch.setattr(train, "send_daily_report", send_daily_report)

    result = train.main()

    assert result == 0
    detector.train.assert_called_once_with(features)
    train.update_anomaly_scores.assert_called_once_with(ANY, scores.to_dict())
    send_daily_report.assert_called_once()


def test_main_skips_training_for_insufficient_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _build_events(10)
    detector_class = Mock()
    send_daily_report = Mock()

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-id")
    monkeypatch.setattr(train.psycopg2, "connect", Mock(return_value=_build_connection_mock()))
    monkeypatch.setattr(train, "create_tables", Mock())
    monkeypatch.setattr(train, "get_events", Mock(return_value=events))
    monkeypatch.setattr(train, "extract_features", Mock())
    monkeypatch.setattr(train, "AnomalyDetector", detector_class)
    monkeypatch.setattr(train, "update_anomaly_scores", Mock())
    monkeypatch.setattr(train, "send_daily_report", send_daily_report)

    result = train.main()

    assert result == 0
    detector_class.assert_not_called()
    send_daily_report.assert_called_once()
    report_stats = send_daily_report.call_args.args[2]
    assert report_stats["insufficient_data"] is True


def test_main_sends_report_when_database_connection_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_daily_report = Mock()

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-id")
    monkeypatch.setattr(train.psycopg2, "connect", Mock(side_effect=RuntimeError("db down")))
    monkeypatch.setattr(train, "send_daily_report", send_daily_report)

    result = train.main()

    assert result == 1
    send_daily_report.assert_called_once()
    report_stats = send_daily_report.call_args.args[2]
    assert report_stats["error"] == "db down"
