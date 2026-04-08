"""Tests for IP enrichment behavior."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from collector.app.database import DatabaseSettings, build_async_engine, create_session_factory, init_database
from collector.app.enricher import IPEnricher


class FrozenClock:
    """Simple mutable clock for deterministic enrichment tests."""

    def __init__(self, current: datetime) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


@pytest.mark.asyncio
async def test_enrich_ip_creates_record_from_geoip_and_abuse_data() -> None:
    engine = build_async_engine(DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:"))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    lookup_counts = {"geo": 0, "abuse": 0}

    def geoip_lookup(ip: str) -> dict[str, str]:
        lookup_counts["geo"] += 1
        assert ip == "203.0.113.8"
        return {"country": "AR", "city": "Cordoba", "asn": "AS64501"}

    async def abuse_lookup(ip: str) -> dict[str, int | bool]:
        lookup_counts["abuse"] += 1
        assert ip == "203.0.113.8"
        return {"abuse_score": 75, "is_tor": True}

    enricher = IPEnricher(
        session_factory,
        geoip_lookup=geoip_lookup,
        abuse_lookup=abuse_lookup,
    )

    record = await enricher.enrich_ip(
        "203.0.113.8",
        last_seen=datetime(2026, 4, 8, 14, 0, tzinfo=timezone.utc),
    )

    assert record.country == "AR"
    assert record.city == "Cordoba"
    assert record.asn == "AS64501"
    assert record.abuse_score == 75
    assert record.is_tor is True
    assert lookup_counts == {"geo": 1, "abuse": 1}
    await engine.dispose()


@pytest.mark.asyncio
async def test_enrich_ip_reuses_fresh_cache_and_updates_last_seen() -> None:
    engine = build_async_engine(DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:"))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    lookup_counts = {"geo": 0, "abuse": 0}
    clock = FrozenClock(datetime(2026, 4, 8, 14, 0, tzinfo=timezone.utc))

    def geoip_lookup(_: str) -> dict[str, str]:
        lookup_counts["geo"] += 1
        return {"country": "US", "city": "New York", "asn": "AS64502"}

    def abuse_lookup(_: str) -> dict[str, int | bool]:
        lookup_counts["abuse"] += 1
        return {"abuse_score": 22, "is_tor": False}

    enricher = IPEnricher(
        session_factory,
        geoip_lookup=geoip_lookup,
        abuse_lookup=abuse_lookup,
        now_provider=clock.now,
    )

    await enricher.enrich_ip(
        "198.51.100.3",
        last_seen=datetime(2026, 4, 8, 14, 0, tzinfo=timezone.utc),
    )
    clock.current = clock.current + timedelta(hours=1)
    record = await enricher.enrich_ip(
        "198.51.100.3",
        last_seen=datetime(2026, 4, 8, 15, 30, tzinfo=timezone.utc),
    )

    assert lookup_counts == {"geo": 1, "abuse": 1}
    assert record.last_seen.isoformat() == "2026-04-08T15:30:00+00:00"
    await engine.dispose()


@pytest.mark.asyncio
async def test_enrich_ip_handles_provider_failures_gracefully() -> None:
    engine = build_async_engine(DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:"))
    session_factory = create_session_factory(engine)
    await init_database(engine)

    def failing_geoip_lookup(_: str) -> None:
        raise RuntimeError("geoip unavailable")

    async def failing_abuse_lookup(_: str) -> None:
        raise RuntimeError("abuse unavailable")

    enricher = IPEnricher(
        session_factory,
        geoip_lookup=failing_geoip_lookup,
        abuse_lookup=failing_abuse_lookup,
    )

    record = await enricher.enrich_ip("192.0.2.25")

    assert record.ip == "192.0.2.25"
    assert record.country is None
    assert record.abuse_score is None
    await engine.dispose()
