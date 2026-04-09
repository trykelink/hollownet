"""Synchronous Telegram reporting for the Hollownet ML pipeline."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def send_daily_report(
    token: str | None,
    chat_id: str | None,
    stats: dict[str, Any],
) -> None:
    """Send a daily ML report to Telegram without surfacing failures."""

    if not token or not chat_id:
        logger.warning("Telegram ML notifier disabled; missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
        return

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": _format_daily_report(stats),
                },
            )
            response.raise_for_status()
    except Exception as exc:
        logger.error("Failed to send ML Telegram report: %s", type(exc).__name__)


def _format_daily_report(stats: dict[str, Any]) -> str:
    top_events = list(stats.get("top_events", []))[:3]
    while len(top_events) < 3:
        top_events.append({"ip": "n/a", "score": "n/a", "timestamp": "n/a"})

    credential = stats.get("top_credential") or "n/a"
    top_country = stats.get("top_country") or {"country": "Unknown", "count": 0}
    lines = [
        "📊 Hollownet — Reporte diario",
        "",
        f"Eventos analizados: {stats.get('total', 0)}",
        f"IPs únicas: {stats.get('unique_ips', 0)}",
        f"Anomalías detectadas (score > 70): {stats.get('anomaly_count', 0)}",
    ]

    if stats.get("insufficient_data"):
        lines.extend(["", "Datos insuficientes para análisis ML (mínimo 50 eventos)"])

    if stats.get("error"):
        lines.extend(["", f"Error del pipeline ML: {stats['error']}"])

    lines.extend(
        [
            "",
            "🔴 Top 3 eventos más anómalos:",
            f"• IP: {top_events[0]['ip']} | Score: {top_events[0]['score']} | {top_events[0]['timestamp']}",
            f"• IP: {top_events[1]['ip']} | Score: {top_events[1]['score']} | {top_events[1]['timestamp']}",
            f"• IP: {top_events[2]['ip']} | Score: {top_events[2]['score']} | {top_events[2]['timestamp']}",
            "",
            f"🔑 Credencial más usada: {credential}",
            f"🌍 País más activo: {top_country['country']} ({top_country['count']} eventos)",
        ]
    )
    return "\n".join(lines)
