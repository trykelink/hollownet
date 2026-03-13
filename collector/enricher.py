"""IP enrichment — geolocation (ip-api.com) + reputation (AbuseIPDB)."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from collector.dynamo import get_ip_cache, set_ip_cache
from collector.models import IPEnrichment

logger = logging.getLogger(__name__)

_IP_API_URL = "http://ip-api.com/json/{ip}?fields=country,countryCode,city,lat,lon,isp,org"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_HTTP_TIMEOUT = 10.0  # seconds


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a loopback, private, or link-local address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _fetch_geo(ip: str, http_client: httpx.Client) -> dict[str, Any]:
    """Call ip-api.com and return the parsed JSON body.

    Returns an empty dict on any network or HTTP error.
    """
    try:
        resp = http_client.get(_IP_API_URL.format(ip=ip), timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "level": "warning",
                    "msg": "ip-api.com request failed",
                    "context": {"ip": ip, "error": str(exc)},
                }
            )
        )
        return {}


def _fetch_abuse(ip: str, api_key: str, http_client: httpx.Client) -> dict[str, Any]:
    """Call AbuseIPDB and return the parsed JSON body.

    Returns an empty dict on any network, HTTP, or parse error — caller
    must treat missing fields as zero-score fallback.
    """
    try:
        resp = http_client.get(
            _ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=_HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "level": "warning",
                    "msg": "AbuseIPDB request failed — using fallback 0",
                    "context": {"ip": ip, "error": str(exc)},
                }
            )
        )
        return {}


def enrich_ip(
    ip: str,
    *,
    dynamo_client: Any | None = None,
    http_client: Optional[httpx.Client] = None,
) -> IPEnrichment:
    """Return an IPEnrichment for *ip*, hitting DynamoDB cache first.

    Private / loopback IPs are returned immediately as an empty enrichment
    without making any external calls.

    Args:
        ip: The source IP to enrich.
        dynamo_client: Optional boto3 DynamoDB client for dependency injection.
        http_client: Optional httpx.Client for dependency injection (tests).

    Raises:
        EnvironmentError: If ABUSEIPDB_API_KEY is not set and a cache miss occurs.
    """
    # --- fast path: private / local IPs ---
    if _is_private(ip):
        return IPEnrichment(
            ip=ip,
            cached_at=datetime.now(timezone.utc).isoformat(),
        )

    # --- DynamoDB cache check ---
    cached = get_ip_cache(ip, client=dynamo_client)
    if cached is not None:
        return cached

    # --- cache miss: need the API key now ---
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "ABUSEIPDB_API_KEY environment variable is not set. "
            "Set it before starting the collector."
        )

    own_client = http_client is None
    client = http_client or httpx.Client()

    try:
        geo = _fetch_geo(ip, client)
        abuse_raw = _fetch_abuse(ip, api_key, client)
    finally:
        if own_client:
            client.close()

    abuse_data: dict[str, Any] = abuse_raw.get("data", {})

    enrichment = IPEnrichment(
        ip=ip,
        country=geo.get("country") or None,
        country_code=geo.get("countryCode") or None,
        city=geo.get("city") or None,
        lat=geo.get("lat"),
        lon=geo.get("lon"),
        isp=geo.get("isp") or geo.get("org") or None,
        abuse_score=int(abuse_data.get("abuseConfidenceScore", 0)),
        total_reports=int(abuse_data.get("totalReports", 0)),
        cached_at=datetime.now(timezone.utc).isoformat(),
    )

    set_ip_cache(enrichment, client=dynamo_client)
    return enrichment
