"""IP enrichment services backed by GeoIP and AbuseIPDB lookups."""

from __future__ import annotations

import inspect
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping

import httpx
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from collector.app.models import IPIntelRecord

logger = logging.getLogger(__name__)

LookupResult = Mapping[str, Any] | BaseModel | None
LookupCallable = Callable[[str], LookupResult | Awaitable[LookupResult]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GeoIPResult(BaseModel):
    """Normalized GeoIP metadata for a source address."""

    country: str | None = None
    city: str | None = None
    asn: str | None = None


class AbuseIPDBResult(BaseModel):
    """Normalized AbuseIPDB metadata for a source address."""

    abuse_score: int | None = None
    is_tor: bool | None = None


class AbuseIPDBClient:
    """Small async client for querying AbuseIPDB."""

    def __init__(
        self,
        api_key: str | None,
        *,
        base_url: str = "https://api.abuseipdb.com/api/v2/check",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._http_client = http_client

    async def lookup(self, ip: str) -> AbuseIPDBResult | None:
        """Fetch AbuseIPDB intelligence for an IP address."""

        if not self._api_key:
            return None

        if self._http_client is not None:
            return await self._fetch(self._http_client, ip)

        async with httpx.AsyncClient(timeout=10.0) as http_client:
            return await self._fetch(http_client, ip)

    async def _fetch(
        self,
        http_client: httpx.AsyncClient,
        ip: str,
    ) -> AbuseIPDBResult:
        response = await http_client.get(
            self._base_url,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Accept": "application/json", "Key": self._api_key},
        )
        response.raise_for_status()
        payload = response.json().get("data", {})
        return AbuseIPDBResult(
            abuse_score=payload.get("abuseConfidenceScore"),
            is_tor=payload.get("isTor"),
        )


class IPEnricher:
    """Cache-aware enrichment service for IP intelligence records."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        geoip_lookup: LookupCallable | None = None,
        abuse_lookup: LookupCallable | None = None,
        freshness_ttl: timedelta = timedelta(hours=24),
        now_provider: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._session_factory = session_factory
        self._geoip_lookup = geoip_lookup
        self._abuse_lookup = abuse_lookup
        self._freshness_ttl = freshness_ttl
        self._now_provider = now_provider

    async def enrich_ip(
        self,
        ip: str,
        *,
        last_seen: datetime | None = None,
    ) -> IPIntelRecord:
        """Create or refresh cached intelligence for a source IP."""

        now = self._now_provider()
        observed_at = _normalize_datetime(last_seen or now)

        async with self._session_factory() as session:
            record = await session.get(IPIntelRecord, ip)

            if record is not None and _is_fresh(record.updated_at, now, self._freshness_ttl):
                normalized_last_seen = _normalize_datetime(record.last_seen)
                if observed_at > normalized_last_seen:
                    record.last_seen = observed_at
                await session.commit()
                await session.refresh(record)
                return _normalize_record_datetimes(record)

            geoip_result = await self._run_geoip_lookup(ip)
            abuse_result = await self._run_abuse_lookup(ip)

            if record is None:
                record = IPIntelRecord(ip=ip, last_seen=observed_at, updated_at=now)
            else:
                record.last_seen = max(_normalize_datetime(record.last_seen), observed_at)
                record.updated_at = now

            if geoip_result is not None:
                record.country = geoip_result.country
                record.city = geoip_result.city
                record.asn = geoip_result.asn

            if abuse_result is not None:
                record.abuse_score = abuse_result.abuse_score
                record.is_tor = abuse_result.is_tor

            session.add(record)
            await session.commit()
            await session.refresh(record)
            return _normalize_record_datetimes(record)

    async def _run_geoip_lookup(self, ip: str) -> GeoIPResult | None:
        if self._geoip_lookup is None:
            return None

        try:
            payload = await _resolve_lookup(self._geoip_lookup, ip)
        except Exception:
            logger.exception("GeoIP lookup failed for %s", ip)
            return None

        if payload is None:
            return None
        return GeoIPResult.model_validate(payload)

    async def _run_abuse_lookup(self, ip: str) -> AbuseIPDBResult | None:
        if self._abuse_lookup is None:
            return None

        try:
            payload = await _resolve_lookup(self._abuse_lookup, ip)
        except Exception:
            logger.exception("AbuseIPDB lookup failed for %s", ip)
            return None

        if payload is None:
            return None
        return AbuseIPDBResult.model_validate(payload)


async def _resolve_lookup(lookup: LookupCallable, ip: str) -> LookupResult:
    result = lookup(ip)
    if inspect.isawaitable(result):
        return await result
    return result


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_fresh(updated_at: datetime, now: datetime, freshness_ttl: timedelta) -> bool:
    return now - _normalize_datetime(updated_at) < freshness_ttl


def _normalize_record_datetimes(record: IPIntelRecord) -> IPIntelRecord:
    record.last_seen = _normalize_datetime(record.last_seen)
    record.updated_at = _normalize_datetime(record.updated_at)
    return record
