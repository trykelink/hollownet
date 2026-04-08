"""Tests for the collector service and FastAPI app."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from collector.app.database import DatabaseSettings, build_async_engine, create_session_factory, init_database
from collector.app.main import CollectorService, CollectorSettings, create_app
from collector.app.models import EventRecord


class StaticLogSource:
    """Return a fixed set of Cowrie log lines for service tests."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    async def read_lines(self) -> list[str]:
        return self._lines


class StubEnricher:
    """Capture enrichment calls without hitting external services."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime | None]] = []

    async def enrich_ip(
        self,
        ip: str,
        *,
        last_seen: datetime | None = None,
    ) -> None:
        self.calls.append((ip, last_seen))


@pytest.mark.asyncio
async def test_collector_service_persists_new_events_and_skips_duplicates(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-service.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    payload = {
        "eventid": "cowrie.login.failed",
        "uuid": "event-1",
        "session": "session-1",
        "src_ip": "203.0.113.50",
        "timestamp": "2026-04-08T12:00:00.000000Z",
        "username": "root",
        "password": "admin",
    }
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([json.dumps(payload), json.dumps(payload)]),
    )

    first_insert_count = await service.poll_once()
    second_insert_count = await service.poll_once()

    async with session_factory() as session:
        stored_count = await session.scalar(select(func.count()).select_from(EventRecord))

    assert first_insert_count == 1
    assert second_insert_count == 0
    assert stored_count == 1
    await engine.dispose()


def test_create_app_exposes_health_and_recent_events(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-app.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    stub_enricher = StubEnricher()
    app = create_app(
        CollectorSettings(
            database_url=database_url,
            container_name="test-cowrie",
            poll_interval_seconds=5,
        ),
        engine=engine,
        session_factory=session_factory,
        log_source=StaticLogSource([]),
        enricher=stub_enricher,
        start_background_task=False,
    )

    async def seed_event() -> None:
        await init_database(engine)
        async with session_factory() as session:
            session.add(
                EventRecord(
                    event_id="recent-1",
                    session="session-99",
                    src_ip="198.51.100.8",
                    timestamp=datetime(2026, 4, 8, 16, 0, tzinfo=timezone.utc),
                    protocol="ssh",
                    username="admin",
                    password="admin",
                    command="pwd",
                    raw={"eventid": "cowrie.command.input"},
                )
            )
            await session.commit()

    import asyncio

    asyncio.run(seed_event())

    with TestClient(app) as client:
        health_response = client.get("/healthz")
        recent_response = client.get("/events/recent?limit=5")

    assert health_response.status_code == 200
    assert health_response.json()["container_name"] == "test-cowrie"
    assert recent_response.status_code == 200
    assert len(recent_response.json()) == 1
    assert recent_response.json()[0]["event_id"] == "recent-1"

    asyncio.run(engine.dispose())
