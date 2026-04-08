"""Tests for the collector service and FastAPI app."""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from collector.app.database import DatabaseSettings, build_async_engine, create_session_factory, init_database
from collector.app.main import (
    CollectorService,
    CollectorSettings,
    CowrieDockerLogSource,
    DockerException,
    NotFound,
    create_app,
)
from collector.app.models import EventRecord
from collector.app.parser import ParsedEvent


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
    ) -> "StubIPIntel":
        self.calls.append((ip, last_seen))
        return StubIPIntel(country="AR", abuse_score=72)


@dataclass
class StubIPIntel:
    """Simple intelligence payload returned by the enricher test double."""

    country: str | None = None
    abuse_score: int | None = None


class StubNotifier:
    """Capture Telegram notifications without performing network I/O."""

    def __init__(self) -> None:
        self.is_configured = True
        self.messages: list[str] = []

    async def send(self, message: str) -> None:
        self.messages.append(message)


def _build_archive_bytes(file_name: str, content: str) -> bytes:
    buffer = BytesIO()
    data = content.encode("utf-8")

    with tarfile.open(fileobj=buffer, mode="w") as archive:
        tar_info = tarfile.TarInfo(name=file_name)
        tar_info.size = len(data)
        archive.addfile(tar_info, BytesIO(data))

    return buffer.getvalue()


def _build_event(
    *,
    event_id: str,
    event_name: str,
    session: str,
    src_ip: str,
    timestamp: datetime,
    username: str | None = None,
    password: str | None = None,
) -> ParsedEvent:
    return ParsedEvent(
        event_id=event_id,
        session=session,
        src_ip=src_ip,
        timestamp=timestamp,
        protocol="ssh",
        username=username,
        password=password,
        command=None,
        raw={"eventid": event_name, "uuid": "sensor-uuid"},
    )


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
    stub_notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([json.dumps(payload), json.dumps(payload)]),
        notifier=stub_notifier,
    )

    first_insert_count = await service.poll_once()
    second_insert_count = await service.poll_once()

    async with session_factory() as session:
        stored_count = await session.scalar(select(func.count()).select_from(EventRecord))

    assert first_insert_count == 1
    assert second_insert_count == 0
    assert stored_count == 1
    assert stub_notifier.messages == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_sends_brute_force_alert_after_five_failed_logins(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-bruteforce.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    base_time = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
    events = [
        _build_event(
            event_id=f"failed-{index}",
            event_name="cowrie.login.failed",
            session=f"session-{index}",
            src_ip="203.0.113.50",
            timestamp=base_time + timedelta(seconds=offset),
        )
        for index, offset in enumerate((0, 10, 20, 30, 60), start=1)
    ]

    inserted_count = await service.store_events(events)

    assert inserted_count == 5
    assert len(notifier.messages) == 1
    assert "Brute force detectado" in notifier.messages[0]
    assert "Intentos: 5 en 60s" in notifier.messages[0]
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_sends_only_one_brute_force_alert_during_sustained_attack(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-sustained-attack.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    base_time = datetime(2026, 4, 8, 12, 20, tzinfo=timezone.utc)
    events = [
        _build_event(
            event_id=f"sustained-{index}",
            event_name="cowrie.login.failed",
            session=f"sustained-session-{index}",
            src_ip="203.0.113.70",
            timestamp=base_time + timedelta(seconds=offset),
        )
        for index, offset in enumerate((0, 5, 10, 15, 20, 25, 30, 35, 40, 45), start=1)
    ]

    inserted_count = await service.store_events(events)

    assert inserted_count == 10
    assert len(notifier.messages) == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_sends_second_brute_force_alert_after_cooldown_expires(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-cooldown-reset.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    base_time = datetime(2026, 4, 8, 12, 30, tzinfo=timezone.utc)
    first_wave = [
        _build_event(
            event_id=f"cooldown-first-{index}",
            event_name="cowrie.login.failed",
            session=f"cooldown-first-session-{index}",
            src_ip="203.0.113.71",
            timestamp=base_time + timedelta(seconds=offset),
        )
        for index, offset in enumerate((0, 5, 10, 15, 20, 25, 30, 35, 40, 45), start=1)
    ]
    second_wave_start = base_time + timedelta(seconds=321)
    second_wave = [
        _build_event(
            event_id=f"cooldown-second-{index}",
            event_name="cowrie.login.failed",
            session=f"cooldown-second-session-{index}",
            src_ip="203.0.113.71",
            timestamp=second_wave_start + timedelta(seconds=offset),
        )
        for index, offset in enumerate((0, 5, 10, 15, 20), start=1)
    ]

    inserted_count = await service.store_events(first_wave + second_wave)

    assert inserted_count == 15
    assert len(notifier.messages) == 2
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_does_not_alert_for_four_failed_logins(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-four-failures.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    base_time = datetime(2026, 4, 8, 12, 5, tzinfo=timezone.utc)
    events = [
        _build_event(
            event_id=f"failed-four-{index}",
            event_name="cowrie.login.failed",
            session=f"session-four-{index}",
            src_ip="203.0.113.51",
            timestamp=base_time.replace(second=offset),
        )
        for index, offset in enumerate((0, 10, 20, 30), start=1)
    ]

    inserted_count = await service.store_events(events)

    assert inserted_count == 4
    assert notifier.messages == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_sends_login_success_alert_immediately(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-login-success.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    event = _build_event(
        event_id="login-success-1",
        event_name="cowrie.login.success",
        session="session-login-success",
        src_ip="203.0.113.52",
        timestamp=datetime(2026, 4, 8, 12, 10, tzinfo=timezone.utc),
        username="root",
        password="toor",
    )

    inserted_count = await service.store_events([event])

    assert inserted_count == 1
    assert len(notifier.messages) == 1
    assert "Login exitoso en honeypot" in notifier.messages[0]
    assert "Usuario: root" in notifier.messages[0]
    assert "Password: toor" in notifier.messages[0]
    await engine.dispose()


@pytest.mark.asyncio
async def test_collector_service_does_not_alert_for_failed_logins_from_different_ips(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-different-ips.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    await init_database(engine)
    notifier = StubNotifier()
    service = CollectorService(
        session_factory,
        enricher=StubEnricher(),
        log_source=StaticLogSource([]),
        notifier=notifier,
    )
    base_time = datetime(2026, 4, 8, 12, 15, tzinfo=timezone.utc)
    events = [
        _build_event(
            event_id=f"failed-different-{index}",
            event_name="cowrie.login.failed",
            session=f"session-different-{index}",
            src_ip=f"203.0.113.{60 + index}",
            timestamp=base_time.replace(second=index),
        )
        for index in range(1, 6)
    ]

    inserted_count = await service.store_events(events)

    assert inserted_count == 5
    assert notifier.messages == []
    await engine.dispose()


def test_cowrie_docker_log_source_reads_lines_from_archive() -> None:
    archive_bytes = _build_archive_bytes(
        "cowrie.json",
        '{"eventid":"cowrie.login.failed"}\n{"eventid":"cowrie.command.input"}\n',
    )
    container = Mock()
    container.get_archive.return_value = ([archive_bytes], {"name": "cowrie.json"})
    docker_client = Mock()
    docker_client.containers.get.return_value = container

    log_source = CowrieDockerLogSource(
        "test-cowrie",
        docker_client=docker_client,
    )

    lines = log_source._read_lines_sync()

    assert lines == [
        '{"eventid":"cowrie.login.failed"}',
        '{"eventid":"cowrie.command.input"}',
    ]
    container.get_archive.assert_called_once()


def test_cowrie_docker_log_source_returns_empty_lines_for_nonzero_exit_code() -> None:
    container = Mock()
    container.get_archive.return_value = ([b"ignored"], 1)
    docker_client = Mock()
    docker_client.containers.get.return_value = container

    log_source = CowrieDockerLogSource(
        "test-cowrie",
        docker_client=docker_client,
    )

    assert log_source._read_lines_sync() == []


def test_cowrie_docker_log_source_returns_empty_lines_when_container_missing() -> None:
    docker_client = Mock()
    docker_client.containers.get.side_effect = NotFound("missing")

    log_source = CowrieDockerLogSource(
        "test-cowrie",
        docker_client=docker_client,
    )

    assert log_source._read_lines_sync() == []


def test_cowrie_docker_log_source_returns_empty_lines_on_docker_exception() -> None:
    docker_client = Mock()
    docker_client.containers.get.side_effect = DockerException("docker failure")

    log_source = CowrieDockerLogSource(
        "test-cowrie",
        docker_client=docker_client,
    )

    assert log_source._read_lines_sync() == []


def test_cowrie_docker_log_source_returns_empty_lines_for_invalid_tar_archive() -> None:
    container = Mock()
    container.get_archive.return_value = ([b"not-a-tar-archive"], {"name": "cowrie.json"})
    docker_client = Mock()
    docker_client.containers.get.return_value = container

    log_source = CowrieDockerLogSource(
        "test-cowrie",
        docker_client=docker_client,
    )

    assert log_source._read_lines_sync() == []


def test_create_app_exposes_health_and_recent_events(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'collector-app.db'}"
    engine = build_async_engine(DatabaseSettings(database_url=database_url))
    session_factory = create_session_factory(engine)
    stub_enricher = StubEnricher()
    stub_notifier = StubNotifier()
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
        notifier=stub_notifier,
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
