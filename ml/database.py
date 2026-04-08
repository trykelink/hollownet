"""Synchronous PostgreSQL helpers for the Hollownet ML pipeline."""

from __future__ import annotations

from typing import Any

import psycopg2.extensions
import psycopg2.extras


def create_tables(conn: psycopg2.extensions.connection) -> None:
    """Create ML persistence tables if they do not already exist."""

    with conn.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS anomaly_scores (
                event_id VARCHAR PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
                score DOUBLE PRECISION NOT NULL,
                scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
    conn.commit()


def get_events(
    conn: psycopg2.extensions.connection,
    hours: int = 168,
) -> list[dict[str, Any]]:
    """Return recent event records enriched with country metadata when available."""

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute(
            """
            SELECT
                e.event_id,
                e.session,
                e.src_ip,
                e.timestamp,
                e.username,
                e.password,
                e.command,
                e.protocol,
                e.raw,
                e.raw ->> 'eventid' AS eventid,
                i.country
            FROM events AS e
            LEFT JOIN ip_intel AS i
                ON i.ip = e.src_ip
            WHERE e.timestamp > NOW() - (%s * INTERVAL '1 hour')
            ORDER BY e.timestamp ASC
            """,
            (hours,),
        )
        return [dict(row) for row in cursor.fetchall()]


def update_anomaly_scores(
    conn: psycopg2.extensions.connection,
    scores: dict[str, float],
) -> None:
    """Upsert normalized anomaly scores keyed by event ID."""

    if not scores:
        return

    rows = [(event_id, float(score)) for event_id, score in scores.items()]
    with conn.cursor() as cursor:
        cursor.executemany(
            """
            INSERT INTO anomaly_scores (event_id, score, scored_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (event_id) DO UPDATE
            SET score = EXCLUDED.score,
                scored_at = EXCLUDED.scored_at
            """,
            rows,
        )
    conn.commit()
