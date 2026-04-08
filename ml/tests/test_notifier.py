"""Tests for ML Telegram reporting."""

from __future__ import annotations

import logging
from unittest.mock import Mock, patch

import httpx
import pytest

from ml.notifier import send_daily_report


def _build_stats() -> dict:
    return {
        "total": 55,
        "unique_ips": 7,
        "anomaly_count": 3,
        "top_events": [
            {"ip": "203.0.113.10", "score": "98.50", "timestamp": "2026-04-08T12:00:00+00:00"},
            {"ip": "203.0.113.11", "score": "88.10", "timestamp": "2026-04-08T12:05:00+00:00"},
            {"ip": "203.0.113.12", "score": "80.20", "timestamp": "2026-04-08T12:10:00+00:00"},
        ],
        "top_credential": "root:admin",
        "top_country": {"country": "AR", "count": 12},
    }


def test_send_daily_report_posts_to_expected_endpoint() -> None:
    response = Mock()
    response.raise_for_status = Mock()
    client = Mock()
    client.post.return_value = response
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=None)

    with patch("ml.notifier.httpx.Client", return_value=client) as client_class:
        send_daily_report("bot-token", "chat-id", _build_stats())

    client_class.assert_called_once_with(timeout=10.0)
    client.post.assert_called_once()
    post_args = client.post.call_args
    assert post_args.args[0] == "https://api.telegram.org/botbot-token/sendMessage"
    assert post_args.kwargs["json"]["chat_id"] == "chat-id"
    assert "📊 Hollownet — Reporte diario" in post_args.kwargs["json"]["text"]
    assert "🔑 Credencial más usada: root:admin" in post_args.kwargs["json"]["text"]
    response.raise_for_status.assert_called_once_with()


def test_send_daily_report_without_token_is_no_op(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with patch("ml.notifier.httpx.Client") as client_class:
        with caplog.at_level(logging.WARNING, logger="ml.notifier"):
            send_daily_report(None, "chat-id", _build_stats())

    client_class.assert_not_called()
    assert any("Telegram ML notifier disabled" in record.message for record in caplog.records)


def test_send_daily_report_logs_errors_for_httpx_failures(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=None)
    client.post.side_effect = httpx.RequestError("boom")

    with patch("ml.notifier.httpx.Client", return_value=client):
        with caplog.at_level(logging.ERROR, logger="ml.notifier"):
            send_daily_report("bot-token", "chat-id", _build_stats())

    assert any("Failed to send ML Telegram report" in record.message for record in caplog.records)
