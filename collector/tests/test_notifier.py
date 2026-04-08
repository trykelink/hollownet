"""Tests for Telegram alert delivery."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from collector.app.notifier import TelegramNotifier


@pytest.mark.asyncio
async def test_send_posts_to_the_expected_telegram_endpoint() -> None:
    response = Mock()
    response.raise_for_status = Mock()
    http_client = AsyncMock()
    http_client.post.return_value = response
    notifier = TelegramNotifier(
        "bot-token",
        "chat-id",
        http_client=http_client,
    )

    await notifier.send("honeypot alert")

    http_client.post.assert_awaited_once_with(
        "https://api.telegram.org/botbot-token/sendMessage",
        json={"chat_id": "chat-id", "text": "honeypot alert"},
    )
    response.raise_for_status.assert_called_once_with()


@pytest.mark.asyncio
async def test_send_without_token_is_a_no_op(
    caplog: pytest.LogCaptureFixture,
) -> None:
    http_client = AsyncMock()
    notifier = TelegramNotifier(
        None,
        "chat-id",
        http_client=http_client,
    )

    with caplog.at_level(logging.WARNING, logger="collector.app.notifier"):
        await notifier.send("honeypot alert")

    http_client.post.assert_not_awaited()
    assert any("Telegram notifier disabled" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_send_logs_error_when_httpx_request_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    http_client = AsyncMock()
    http_client.post.side_effect = httpx.RequestError("boom")
    notifier = TelegramNotifier(
        "bot-token",
        "chat-id",
        http_client=http_client,
    )

    with caplog.at_level(logging.ERROR, logger="collector.app.notifier"):
        await notifier.send("honeypot alert")

    assert any("Failed to send Telegram alert" in record.message for record in caplog.records)
