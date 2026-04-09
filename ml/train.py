"""Main entrypoint for Hollownet daily anomaly scoring."""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any

import pandas as pd
import psycopg2

try:
    from ml.database import create_tables, get_events, update_anomaly_scores
    from ml.features import extract_features
    from ml.model import ANOMALY_ALERT_THRESHOLD, MIN_TRAINING_EVENTS, AnomalyDetector
    from ml.notifier import send_daily_report
except ImportError:  # pragma: no cover
    from database import create_tables, get_events, update_anomaly_scores
    from features import extract_features
    from model import ANOMALY_ALERT_THRESHOLD, MIN_TRAINING_EVENTS, AnomalyDetector
    from notifier import send_daily_report

logger = logging.getLogger(__name__)
MODEL_PATH = "/app/models/anomaly_detector.pkl"


def main() -> int:
    """Run the daily ML pipeline end-to-end."""

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    database_url = os.getenv("DATABASE_URL")
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    stats: dict[str, Any] = _empty_stats()
    events: list[dict[str, Any]] = []

    if not database_url:
        logger.error("DATABASE_URL is required for the ML pipeline")
        stats["error"] = "DATABASE_URL no está configurada"
        send_daily_report(telegram_bot_token, telegram_chat_id, stats)
        return 1

    try:
        normalized_database_url = _normalize_database_url(database_url)
        logger.info("Connecting to PostgreSQL for ML pipeline")
        with psycopg2.connect(normalized_database_url) as conn:
            create_tables(conn)
            logger.info("Ensured anomaly_scores table exists")

            events = get_events(conn)
            logger.info("Loaded %s events for anomaly scoring", len(events))
            stats = _build_base_stats(events)

            if len(events) < MIN_TRAINING_EVENTS:
                logger.info("Insufficient data for anomaly model: %s events", len(events))
                stats["insufficient_data"] = True
                send_daily_report(telegram_bot_token, telegram_chat_id, stats)
                return 0

            features = extract_features(events)
            logger.info("Extracted %s feature rows", len(features))
            detector = AnomalyDetector()
            detector.train(features)
            detector.save(MODEL_PATH)
            logger.info("Saved trained anomaly detector to %s", MODEL_PATH)

            scores = detector.score(features)
            update_anomaly_scores(conn, scores.to_dict())
            logger.info("Persisted %s anomaly scores", len(scores))

            stats = _build_scored_stats(events, scores)
            send_daily_report(telegram_bot_token, telegram_chat_id, stats)
            return 0
    except Exception as exc:
        logger.exception("ML pipeline execution failed")
        if not events:
            stats = _empty_stats()
        else:
            stats = _build_base_stats(events)
        stats["error"] = str(exc)
        send_daily_report(telegram_bot_token, telegram_chat_id, stats)
        return 1


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    return database_url


def _build_base_stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    credential_counter = Counter()
    country_counter = Counter()

    for event in events:
        username = event.get("username")
        password = event.get("password")
        if username is not None:
            credential_counter[f"{username}:{password or '(none)'}"] += 1

        country_counter[event.get("country") or "Unknown"] += 1

    top_credential = credential_counter.most_common(1)[0][0] if credential_counter else "n/a"
    if country_counter:
        country_name, country_count = country_counter.most_common(1)[0]
    else:
        country_name, country_count = "Unknown", 0

    return {
        "total": len(events),
        "unique_ips": len({event.get("src_ip") for event in events if event.get("src_ip")}),
        "anomaly_count": 0,
        "top_events": [],
        "top_credential": top_credential,
        "top_country": {"country": country_name, "count": country_count},
    }


def _build_scored_stats(
    events: list[dict[str, Any]],
    scores: pd.Series,
) -> dict[str, Any]:
    stats = _build_base_stats(events)
    score_map = {str(event_id): float(score) for event_id, score in scores.items()}
    event_lookup = {str(event["event_id"]): event for event in events}
    top_events: list[dict[str, Any]] = []

    for event_id, score in sorted(score_map.items(), key=lambda item: item[1], reverse=True)[:3]:
        event = event_lookup.get(event_id, {})
        top_events.append(
            {
                "ip": event.get("src_ip", "n/a"),
                "score": f"{score:.2f}",
                "timestamp": _format_timestamp(event.get("timestamp")),
            }
        )

    stats["anomaly_count"] = sum(
        1 for score in score_map.values() if score > ANOMALY_ALERT_THRESHOLD
    )
    stats["top_events"] = top_events
    return stats


def _format_timestamp(value: Any) -> str:
    if value is None:
        return "n/a"

    return str(value)


def _empty_stats() -> dict[str, Any]:
    return {
        "total": 0,
        "unique_ips": 0,
        "anomaly_count": 0,
        "top_events": [],
        "top_credential": "n/a",
        "top_country": {"country": "Unknown", "count": 0},
    }


if __name__ == "__main__":
    raise SystemExit(main())
