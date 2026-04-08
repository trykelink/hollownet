"""Telegram notification helpers for collector alerts."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Send collector alerts to a Telegram chat."""

    def __init__(
        self,
        bot_token: str | None,
        chat_id: str | None,
        *,
        http_client: httpx.AsyncClient | None = None,
        base_url: str = "https://api.telegram.org",
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._http_client = http_client
        self._base_url = base_url.rstrip("/")

    @property
    def is_configured(self) -> bool:
        """Return True if both token and chat_id are set."""
        return bool(self._bot_token and self._chat_id)

    async def send(self, message: str) -> None:
        """Send a plain-text Telegram message without surfacing failures."""

        if not self.is_configured:
            logger.warning("Telegram notifier disabled; missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
            return

        request_url = f"{self._base_url}/bot{self._bot_token}/sendMessage"
        payload = {"chat_id": self._chat_id, "text": message}

        try:
            if self._http_client is not None:
                response = await self._http_client.post(request_url, json=payload)
                response.raise_for_status()
                return

            async with httpx.AsyncClient(timeout=10.0) as http_client:
                response = await http_client.post(request_url, json=payload)
                response.raise_for_status()
        except Exception:
            logger.error("Failed to send Telegram alert", exc_info=True)
