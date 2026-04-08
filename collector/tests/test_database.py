"""Tests for collector database helpers."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect

from collector.app import database


@pytest.mark.asyncio
async def test_create_session_factory_returns_async_session() -> None:
    engine = database.build_async_engine(
        database.DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:")
    )
    session_factory = database.create_session_factory(engine)

    async with session_factory() as session:
        assert session.bind is engine

    await engine.dispose()


def test_database_settings_use_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///tmp/hollownet.db")

    settings = database.DatabaseSettings()

    assert settings.database_url == "sqlite+aiosqlite:///tmp/hollownet.db"


@pytest.mark.asyncio
async def test_get_session_uses_current_session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = database.build_async_engine(
        database.DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:")
    )
    session_factory = database.create_session_factory(engine)
    monkeypatch.setattr(database, "SessionFactory", session_factory)

    session_generator = database.get_session()
    session = await anext(session_generator)

    assert session.bind is engine

    await session_generator.aclose()
    await engine.dispose()


@pytest.mark.asyncio
async def test_init_database_creates_expected_tables() -> None:
    engine = database.build_async_engine(
        database.DatabaseSettings(database_url="sqlite+aiosqlite:///:memory:")
    )

    await database.init_database(engine)

    async with engine.begin() as connection:
        table_names = await connection.run_sync(
            lambda sync_connection: inspect(sync_connection).get_table_names()
        )

    assert set(table_names) >= {"events", "ip_intel"}
    await engine.dispose()
