"""ORM models for Cowrie events and IP enrichment data."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from collector.app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventRecord(Base):
    """Persisted Cowrie event ready for analytics and dashboards."""

    __tablename__ = "events"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    session: Mapped[str] = mapped_column(String(255), index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    protocol: Mapped[str] = mapped_column(String(32), default="ssh")
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON)
    inserted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        index=True,
    )


class IPIntelRecord(Base):
    """Cached threat-intelligence data for a source IP address."""

    __tablename__ = "ip_intel"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    country: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    abuse_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_tor: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
