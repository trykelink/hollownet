"""Unit tests for collector/enricher.py — all external calls mocked."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.enricher import enrich_ip
from collector.models import IPEnrichment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_geo_response(
    country: str = "Germany",
    country_code: str = "DE",
    city: str = "Frankfurt",
    lat: float = 50.11,
    lon: float = 8.68,
    isp: str = "Hetzner Online GmbH",
) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "country": country,
        "countryCode": country_code,
        "city": city,
        "lat": lat,
        "lon": lon,
        "isp": isp,
        "org": isp,
    }
    return resp


def _make_abuse_response(score: int = 75, reports: int = 10) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
        }
    }
    return resp


def _make_http_client(geo_resp: MagicMock, abuse_resp: MagicMock) -> MagicMock:
    """Return a mock httpx.Client whose .get() returns geo then abuse responses."""
    client = MagicMock(spec=httpx.Client)
    client.get.side_effect = [geo_resp, abuse_resp]
    return client


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PUBLIC_IP = "1.2.3.4"  # genuinely public; TEST-NET ranges (203.0.113.0/24) are private in Python 3.11+


@pytest.fixture
def mock_dynamo_no_cache() -> MagicMock:
    """DynamoDB client that always returns a cache miss."""
    m = MagicMock()
    with patch("collector.enricher.get_ip_cache", return_value=None), \
         patch("collector.enricher.set_ip_cache") as mock_set:
        yield m, mock_set


@pytest.fixture
def mock_dynamo_cache_hit() -> IPEnrichment:
    """Pre-built IPEnrichment that DynamoDB returns on cache hit."""
    return IPEnrichment(
        ip="1.2.3.4",
        country="Germany",
        country_code="DE",
        city="Frankfurt",
        lat=50.11,
        lon=8.68,
        isp="Hetzner Online GmbH",
        abuse_score=75,
        total_reports=10,
        cached_at="2026-03-13T00:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_cache_hit_returns_cached_enrichment_without_http(mock_dynamo_cache_hit: IPEnrichment) -> None:
    """On cache hit, no HTTP calls should be made."""
    with patch("collector.enricher.get_ip_cache", return_value=mock_dynamo_cache_hit) as mock_get, \
         patch("collector.enricher.set_ip_cache") as mock_set, \
         patch("collector.enricher.httpx.Client") as mock_http_cls:

        result = enrich_ip(PUBLIC_IP)

    assert result == mock_dynamo_cache_hit
    mock_get.assert_called_once_with(PUBLIC_IP, client=None)
    mock_set.assert_not_called()
    mock_http_cls.assert_not_called()


def test_cache_miss_calls_both_apis_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    """On cache miss, both ip-api and AbuseIPDB are called and result is cached."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    geo_resp = _make_geo_response()
    abuse_resp = _make_abuse_response()
    http_client = _make_http_client(geo_resp, abuse_resp)

    with patch("collector.enricher.get_ip_cache", return_value=None), \
         patch("collector.enricher.set_ip_cache") as mock_set:

        result = enrich_ip(PUBLIC_IP, http_client=http_client)

    assert result.ip == PUBLIC_IP
    assert result.country == "Germany"
    assert result.country_code == "DE"
    assert result.city == "Frankfurt"
    assert result.lat == 50.11
    assert result.lon == 8.68
    assert result.isp == "Hetzner Online GmbH"
    assert result.abuse_score == 75
    assert result.total_reports == 10

    # Both endpoints were called
    assert http_client.get.call_count == 2

    # Result was written to cache
    mock_set.assert_called_once()
    cached_arg = mock_set.call_args[0][0]
    assert cached_arg.ip == PUBLIC_IP


def test_abuseipdb_failure_falls_back_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """AbuseIPDB network failure must not raise — abuse_score defaults to 0."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    geo_resp = _make_geo_response()

    abuse_resp = MagicMock(spec=httpx.Response)
    abuse_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "503", request=MagicMock(), response=MagicMock()
    )

    http_client = _make_http_client(geo_resp, abuse_resp)

    with patch("collector.enricher.get_ip_cache", return_value=None), \
         patch("collector.enricher.set_ip_cache") as mock_set:

        result = enrich_ip(PUBLIC_IP, http_client=http_client)

    assert result.abuse_score == 0
    assert result.total_reports == 0
    assert result.country == "Germany"  # geo still populated
    mock_set.assert_called_once()


def test_ip_api_failure_falls_back_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """ip-api.com network failure must not raise — all geo fields are None."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    geo_resp = MagicMock(spec=httpx.Response)
    geo_resp.raise_for_status.side_effect = httpx.ConnectError("timeout")

    abuse_resp = _make_abuse_response(score=50, reports=5)

    http_client = _make_http_client(geo_resp, abuse_resp)

    with patch("collector.enricher.get_ip_cache", return_value=None), \
         patch("collector.enricher.set_ip_cache") as mock_set:

        result = enrich_ip(PUBLIC_IP, http_client=http_client)

    assert result.country is None
    assert result.city is None
    assert result.lat is None
    assert result.lon is None
    assert result.abuse_score == 50
    mock_set.assert_called_once()


@pytest.mark.parametrize(
    "private_ip",
    [
        "192.168.1.1",
        "192.168.100.55",
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.0.5",
        "::1",
    ],
)
def test_private_ips_return_empty_enrichment_without_api_calls(
    private_ip: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Private/loopback IPs must return empty enrichment with no API calls."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    with patch("collector.enricher.get_ip_cache") as mock_get, \
         patch("collector.enricher.set_ip_cache") as mock_set, \
         patch("collector.enricher.httpx.Client") as mock_http_cls:

        result = enrich_ip(private_ip)

    assert result.ip == private_ip
    assert result.country is None
    assert result.abuse_score == 0
    mock_get.assert_not_called()
    mock_set.assert_not_called()
    mock_http_cls.assert_not_called()


def test_missing_api_key_raises_on_cache_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clear EnvironmentError is raised when ABUSEIPDB_API_KEY is absent."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    with patch("collector.enricher.get_ip_cache", return_value=None):
        with pytest.raises(EnvironmentError, match="ABUSEIPDB_API_KEY"):
            enrich_ip(PUBLIC_IP)
