"""Tests for collector ORM models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from collector.app.database import DatabaseSettings, build_async_engine, create_session_factory, init_database
from collector.app.models import EventRecord, IPIntelRecord


@pytest.mark.asyncio
async def test_event_record_persists_expected_fields() -> None:
    engine = build_async_engine(DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:"))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    async with session_factory() as session:
        record = EventRecord(
            event_id="event-1",
            session="session-1",
            src_ip="192.0.2.10",
            timestamp=datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc),
            protocol="ssh",
            username="root",
            password="toor",
            command="uname -a",
            raw={"eventid": "cowrie.command.input"},
        )
        session.add(record)
        await session.commit()

        stored_record = await session.scalar(
            select(EventRecord).where(EventRecord.event_id == "event-1")
        )

    assert stored_record is not None
    assert stored_record.id is not None
    assert stored_record.inserted_at is not None
    assert stored_record.command == "uname -a"
    await engine.dispose()


@pytest.mark.asyncio
async def test_ip_intel_record_persists_cached_metadata() -> None:
    engine = build_async_engine(DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:"))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    async with session_factory() as session:
        record = IPIntelRecord(
            ip="198.51.100.5",
            country="AR",
            city="Buenos Aires",
            asn="AS64500",
            abuse_score=55,
            is_tor=False,
            last_seen=datetime(2026, 4, 8, 10, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 4, 8, 10, 30, tzinfo=timezone.utc),
        )
        session.add(record)
        await session.commit()

        stored_record = await session.get(IPIntelRecord, "198.51.100.5")

    assert stored_record is not None
    assert stored_record.country == "AR"
    assert stored_record.asn == "AS64500"
    assert stored_record.abuse_score == 55
    await engine.dispose()
