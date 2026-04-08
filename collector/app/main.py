"""FastAPI application and background poller for the Cowrie collector."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import tarfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from collector.app.database import (
    DEFAULT_DATABASE_URL,
    DatabaseSettings,
    build_async_engine,
    create_session_factory,
    init_database,
)
from collector.app.enricher import AbuseIPDBClient, IPEnricher
from collector.app.models import EventRecord, IPIntelRecord
from collector.app.notifier import TelegramNotifier
from collector.app.parser import ParsedEvent, parse_log_lines

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:  # pragma: no cover
    docker = None

    class DockerException(Exception):
        """Fallback Docker exception when the SDK is unavailable."""

    class NotFound(DockerException):
        """Fallback not-found error when the Docker SDK is unavailable."""


logger = logging.getLogger(__name__)

DEFAULT_COWRIE_LOG_PATH = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=60)
DEFAULT_ALERT_COOLDOWN_SECONDS = 300


class CollectorSettings(BaseModel):
    """Runtime settings for the collector service."""

    model_config = ConfigDict(extra="ignore")

    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL))
    container_name: str = Field(default_factory=lambda: os.getenv("DOCKER_CONTAINER_NAME", "hollownet-cowrie"))
    cowrie_log_path: str = DEFAULT_COWRIE_LOG_PATH
    poll_interval_seconds: int = 30
    alert_cooldown_seconds: int = Field(
        default_factory=lambda: int(os.getenv("ALERT_COOLDOWN_SECONDS", str(DEFAULT_ALERT_COOLDOWN_SECONDS)))
    )
    abuseipdb_api_key: str | None = Field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY"))
    telegram_bot_token: str | None = Field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN"))
    telegram_chat_id: str | None = Field(default_factory=lambda: os.getenv("TELEGRAM_CHAT_ID"))


class HealthResponse(BaseModel):
    """Response model for the collector health endpoint."""

    status: str
    container_name: str
    poll_interval_seconds: int


class EventResponse(BaseModel):
    """Response model for recent stored events."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    session: str
    src_ip: str
    protocol: str
    username: str | None
    password: str | None
    command: str | None
    raw: dict[str, Any]


class CowrieDockerLogSource:
    """Read Cowrie JSON logs from the honeypot container through Docker SDK."""

    def __init__(
        self,
        container_name: str,
        cowrie_log_path: str = DEFAULT_COWRIE_LOG_PATH,
        *,
        docker_client: Any | None = None,
    ) -> None:
        self._container_name = container_name
        self._cowrie_log_path = cowrie_log_path
        self._docker_client = docker_client

    async def read_lines(self) -> list[str]:
        """Fetch Cowrie JSON log lines from the container."""

        return await asyncio.to_thread(self._read_lines_sync)

    def _read_lines_sync(self) -> list[str]:
        if docker is None and self._docker_client is None:
            logger.warning("Docker SDK is unavailable; skipping Cowrie poll")
            return []

        try:
            if self._docker_client is None:
                self._docker_client = docker.from_env()

            container = self._docker_client.containers.get(self._container_name)
            archive_result = container.get_archive(self._cowrie_log_path)
        except NotFound:
            logger.warning("Cowrie container %s was not found", self._container_name)
            return []
        except DockerException:
            logger.exception("Failed to read Cowrie logs via Docker SDK")
            return []

        exit_code, output = _decode_archive_result(archive_result)
        if exit_code not in (0, None):
            logger.warning("Cowrie log read returned exit code %s", exit_code)
            return []

        try:
            return _extract_tar_file_lines(output)
        except (tarfile.TarError, OSError):
            logger.exception("Failed to extract Cowrie log archive from Docker SDK")
            return []


class CollectorService:
    """Persist parsed Cowrie events and trigger enrichment."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        enricher: IPEnricher,
        log_source: CowrieDockerLogSource,
        notifier: TelegramNotifier,
        poll_interval_seconds: int = 30,
        alert_cooldown_seconds: int = DEFAULT_ALERT_COOLDOWN_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._enricher = enricher
        self._log_source = log_source
        self._notifier = notifier
        self._poll_interval_seconds = poll_interval_seconds
        self._failed_login_attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self._alert_cooldowns: dict[str, datetime] = {}
        self._alert_cooldown = timedelta(seconds=alert_cooldown_seconds)

    async def poll_once(self) -> int:
        """Read, parse, persist, and enrich one batch of Cowrie logs."""

        log_lines = await self._log_source.read_lines()
        parsed_events = parse_log_lines(log_lines)
        return await self.store_events(parsed_events)

    async def store_events(self, events: list[ParsedEvent]) -> int:
        """Store only new events, then lazily enrich the corresponding IPs."""

        if not events:
            return 0

        deduplicated_events = list({event.event_id: event for event in events}.values())
        event_ids = [event.event_id for event in deduplicated_events]

        async with self._session_factory() as session:
            result = await session.execute(
                select(EventRecord.event_id).where(EventRecord.event_id.in_(event_ids))
            )
            existing_event_ids = set(result.scalars().all())
            new_events = [event for event in deduplicated_events if event.event_id not in existing_event_ids]

            for event in new_events:
                session.add(
                    EventRecord(
                        event_id=event.event_id,
                        session=event.session,
                        src_ip=event.src_ip,
                        timestamp=event.timestamp,
                        protocol=event.protocol,
                        username=event.username,
                        password=event.password,
                        command=event.command,
                        raw=event.raw,
                    )
                )

            await session.commit()

        for event in new_events:
            intel_record: IPIntelRecord | None = None
            try:
                intel_record = await self._enricher.enrich_ip(event.src_ip, last_seen=event.timestamp)
            except Exception:
                logger.exception("IP enrichment failed for %s", event.src_ip)

            await self._maybe_send_alert(event, intel_record)

        return len(new_events)

    async def run(self, stop_event: asyncio.Event) -> None:
        """Run the collector polling loop until asked to stop."""

        logger.info("Collector poller starting")
        while not stop_event.is_set():
            try:
                await self.poll_once()
            except Exception:
                logger.exception("Collector poll iteration failed")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self._poll_interval_seconds)
            except asyncio.TimeoutError:
                continue

    async def _maybe_send_alert(
        self,
        event: ParsedEvent,
        intel_record: IPIntelRecord | None,
    ) -> None:
        event_name = str(event.raw.get("eventid", ""))

        if event_name == "cowrie.login.success":
            await self._notifier.send(_build_login_success_alert(event, intel_record))
            return

        if event_name != "cowrie.login.failed":
            return

        attempts = self._failed_login_attempts[event.src_ip]
        attempts.append(event.timestamp)
        window_start = event.timestamp - BRUTE_FORCE_WINDOW
        while attempts and attempts[0] < window_start:
            attempts.popleft()

        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            last_alert_at = self._alert_cooldowns.get(event.src_ip)
            if last_alert_at is not None and event.timestamp - last_alert_at < self._alert_cooldown:
                logger.debug("Skipping brute force alert for %s; cooldown active", event.src_ip)
                return

            await self._notifier.send(_build_brute_force_alert(event.src_ip, len(attempts), intel_record))
            self._alert_cooldowns[event.src_ip] = event.timestamp


def create_app(
    settings: CollectorSettings | None = None,
    *,
    engine: AsyncEngine | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    log_source: CowrieDockerLogSource | None = None,
    enricher: IPEnricher | None = None,
    notifier: TelegramNotifier | None = None,
    start_background_task: bool = True,
) -> FastAPI:
    """Create the FastAPI collector application."""

    resolved_settings = settings or CollectorSettings()
    managed_engine = engine

    if session_factory is None:
        managed_engine = engine or build_async_engine(
            DatabaseSettings(database_url=resolved_settings.database_url)
        )
        session_factory = create_session_factory(managed_engine)

    resolved_log_source = log_source or CowrieDockerLogSource(
        resolved_settings.container_name,
        resolved_settings.cowrie_log_path,
    )
    resolved_enricher = enricher or IPEnricher(
        session_factory,
        abuse_lookup=AbuseIPDBClient(resolved_settings.abuseipdb_api_key).lookup,
    )
    @asynccontextmanager
    async def lifespan(application: FastAPI):  # noqa: ANN001
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        logger.setLevel(log_level)
        logging.getLogger("collector").setLevel(log_level)
        logging.getLogger("app").setLevel(log_level)
        logging.getLogger().setLevel(log_level)

        resolved_notifier = notifier or TelegramNotifier(
            resolved_settings.telegram_bot_token,
            resolved_settings.telegram_chat_id,
        )
        if not resolved_notifier.is_configured:
            logger.warning("Telegram alerts disabled; missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

        application.state.collector_service = CollectorService(
            session_factory,
            enricher=resolved_enricher,
            log_source=resolved_log_source,
            notifier=resolved_notifier,
            poll_interval_seconds=resolved_settings.poll_interval_seconds,
            alert_cooldown_seconds=resolved_settings.alert_cooldown_seconds,
        )

        if managed_engine is not None:
            await init_database(managed_engine)

        if start_background_task:
            application.state.collector_task = asyncio.create_task(
                application.state.collector_service.run(application.state.stop_event)
            )

        yield

        application.state.stop_event.set()

        collector_task = application.state.collector_task
        if collector_task is not None:
            await collector_task

        if managed_engine is not None:
            await managed_engine.dispose()

    app = FastAPI(title="Hollownet Collector", lifespan=lifespan)
    app.state.settings = resolved_settings
    app.state.engine = managed_engine
    app.state.session_factory = session_factory
    app.state.collector_service = None
    app.state.stop_event = asyncio.Event()
    app.state.collector_task = None

    async def get_db_session() -> AsyncSession:
        async with session_factory() as session:
            yield session

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz(
        session: AsyncSession = Depends(get_db_session),
    ) -> HealthResponse:
        """Check service health and verify database connectivity."""
        await session.execute(text("SELECT 1"))
        return HealthResponse(
            status="ok",
            container_name=resolved_settings.container_name,
            poll_interval_seconds=resolved_settings.poll_interval_seconds,
        )

    @app.get("/events/recent", response_model=list[EventResponse])
    async def recent_events(
        limit: int = Query(default=20, ge=1, le=100),
        session: AsyncSession = Depends(get_db_session),
    ) -> list[EventResponse]:
        """Return the most recent Cowrie events ordered by timestamp descending."""
        result = await session.execute(
            select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(limit)
        )
        return [
            EventResponse.model_validate(event_record)
            for event_record in result.scalars().all()
        ]

    return app


def _decode_archive_result(archive_result: Any) -> tuple[int | None, bytes]:
    if isinstance(archive_result, tuple):
        stream, metadata = archive_result
        exit_code = metadata if isinstance(metadata, int) else None
        return exit_code, b"".join(stream)

    return getattr(archive_result, "exit_code", None), getattr(archive_result, "output", b"")


def _build_brute_force_alert(
    src_ip: str,
    attempt_count: int,
    intel_record: IPIntelRecord | None,
) -> str:
    country, abuse_score = _format_intel(intel_record)
    return (
        "🚨 Brute force detectado\n"
        f"IP: {src_ip}\n"
        f"País: {country} ({abuse_score}/100)\n"
        f"Intentos: {attempt_count} en 60s"
    )


def _build_login_success_alert(
    event: ParsedEvent,
    intel_record: IPIntelRecord | None,
) -> str:
    country, abuse_score = _format_intel(intel_record)
    return (
        "⚠️ Login exitoso en honeypot\n"
        f"IP: {event.src_ip}\n"
        f"País: {country} ({abuse_score}/100)\n"
        f"Usuario: {event.username or '-'}\n"
        f"Password: {event.password or '-'}"
    )


def _format_intel(intel_record: IPIntelRecord | None) -> tuple[str, str]:
    country = intel_record.country if intel_record is not None and intel_record.country else "Unknown"
    abuse_score = (
        str(intel_record.abuse_score)
        if intel_record is not None and intel_record.abuse_score is not None
        else "n/a"
    )
    return country, abuse_score


def _extract_tar_file_lines(archive_bytes: bytes) -> list[str]:
    tar_buffer = io.BytesIO(archive_bytes)
    with tarfile.open(fileobj=tar_buffer, mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue

            extracted_file = archive.extractfile(member)
            if extracted_file is None:
                continue

            return extracted_file.read().decode("utf-8", errors="ignore").splitlines()

    return []


try:
    app = create_app()
except Exception:  # pragma: no cover
    logger.warning("Default app initialization skipped; DATABASE_URL must be set explicitly")
    app = FastAPI(title="Hollownet Collector")
