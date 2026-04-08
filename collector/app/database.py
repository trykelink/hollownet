"""Database configuration and async session helpers for the collector."""

from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = ""


class DatabaseSettings(BaseModel):
    """Runtime configuration for database connectivity."""

    model_config = ConfigDict(extra="ignore")

    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL))
    echo_sql: bool = False


class Base(DeclarativeBase):
    """Base declarative model class for all ORM tables."""


def build_async_engine(settings: DatabaseSettings | None = None) -> AsyncEngine:
    """Create an async SQLAlchemy engine from runtime settings."""

    resolved_settings = settings or DatabaseSettings()
    logger.debug("Creating async database engine for collector")
    return create_async_engine(
        resolved_settings.database_url,
        echo=resolved_settings.echo_sql,
        future=True,
    )


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory for a specific engine."""

    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


engine: AsyncEngine | None = None
SessionFactory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the default async engine, creating it on first use."""

    global engine

    if engine is None:
        engine = build_async_engine()
    return engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the default session factory, creating it on first use."""

    global SessionFactory

    if SessionFactory is None:
        SessionFactory = create_session_factory(get_engine())
    return SessionFactory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for FastAPI dependencies."""

    async with get_session_factory()() as session:
        yield session


async def init_database(target_engine: AsyncEngine | None = None) -> None:
    """Create all collector tables if they do not already exist."""

    from collector.app import models  # noqa: F401

    resolved_engine = target_engine or get_engine()
    async with resolved_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
