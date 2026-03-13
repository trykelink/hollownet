"""Integration-style tests for collector.main with mocked dependencies."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.main import app, get_dynamo_client
from collector.models import EnrichedEvent, IPEnrichment


@pytest.fixture
def client() -> tuple[TestClient, object]:
    ddb_client = object()
    app.dependency_overrides[get_dynamo_client] = lambda: ddb_client

    with TestClient(app) as test_client:
        yield test_client, ddb_client

    app.dependency_overrides.clear()


@pytest.fixture
def event_payload() -> dict[str, object]:
    return {
        "event_id": "evt-001",
        "timestamp": "2026-03-13T12:00:00.000000Z",
        "src_ip": "1.2.3.4",
        "event_type": "login_failed",
        "session_id": "sess-001",
        "username": "root",
        "password": "toor",
        "command": None,
        "raw_payload": {"eventid": "cowrie.login.failed"},
    }


def test_post_events_happy_path_calls_enrichment_and_persists(
    client: tuple[TestClient, object],
    event_payload: dict[str, object],
) -> None:
    test_client, ddb_client = client
    enrichment = IPEnrichment(
        ip="1.2.3.4",
        country="Germany",
        country_code="DE",
        city="Frankfurt",
        lat=50.11,
        lon=8.68,
        isp="Hetzner",
        abuse_score=75,
        total_reports=10,
        cached_at="2026-03-13T12:00:01+00:00",
    )

    with patch("collector.main.enricher.enrich_ip", return_value=enrichment) as mock_enrich, \
         patch("collector.main.dynamo.put_event") as mock_put_event:
        response = test_client.post("/events", json=event_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["src_ip"] == "1.2.3.4"
    assert data["country"] == "Germany"
    assert data["abuse_score"] == 75
    mock_enrich.assert_called_once_with("1.2.3.4", dynamo_client=ddb_client)
    mock_put_event.assert_called_once()
    persisted_event = mock_put_event.call_args.args[0]
    assert isinstance(persisted_event, EnrichedEvent)
    assert persisted_event.country == "Germany"
    assert persisted_event.abuse_score == 75


def test_post_events_private_ip_skips_enrichment(
    client: tuple[TestClient, object],
    event_payload: dict[str, object],
) -> None:
    test_client, _ = client
    event_payload["src_ip"] = "192.168.1.10"

    with patch("collector.main.enricher.enrich_ip") as mock_enrich, \
         patch("collector.main.dynamo.put_event") as mock_put_event:
        response = test_client.post("/events", json=event_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["src_ip"] == "192.168.1.10"
    assert data["abuse_score"] == 0
    assert data["country"] is None
    mock_enrich.assert_not_called()
    mock_put_event.assert_called_once()


def test_post_events_dynamo_failure_returns_503(
    client: tuple[TestClient, object],
    event_payload: dict[str, object],
) -> None:
    test_client, _ = client
    enrichment = IPEnrichment(ip="1.2.3.4", cached_at="2026-03-13T12:00:01+00:00")

    with patch("collector.main.enricher.enrich_ip", return_value=enrichment), \
         patch("collector.main.dynamo.put_event", side_effect=RuntimeError("ddb down")):
        response = test_client.post("/events", json=event_payload)

    assert response.status_code == 503
    assert response.json() == {
        "error": "service_unavailable",
        "detail": "Failed to persist event to DynamoDB",
    }


def test_get_events_without_filters(client: tuple[TestClient, object]) -> None:
    test_client, ddb_client = client

    with patch("collector.main.dynamo.get_events", return_value=[]) as mock_get_events:
        response = test_client.get("/events")

    assert response.status_code == 200
    assert response.json() == []
    mock_get_events.assert_called_once_with(
        src_ip=None,
        event_type=None,
        limit=20,
        client=ddb_client,
    )


def test_get_events_with_filters(client: tuple[TestClient, object]) -> None:
    test_client, ddb_client = client
    mocked_events = [
        EnrichedEvent(
            event_id="evt-002",
            timestamp="2026-03-13T13:00:00.000000Z",
            src_ip="1.2.3.4",
            event_type="command",
            session_id="sess-002",
            username="root",
            password="toor",
            command="uname -a",
            raw_payload={"eventid": "cowrie.command.input"},
            country="Germany",
            abuse_score=70,
            total_reports=5,
        )
    ]

    with patch("collector.main.dynamo.get_events", return_value=mocked_events) as mock_get_events:
        response = test_client.get("/events", params={"src_ip": "1.2.3.4", "event_type": "command", "limit": 5})

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["event_id"] == "evt-002"
    mock_get_events.assert_called_once_with(
        src_ip="1.2.3.4",
        event_type="command",
        limit=5,
        client=ddb_client,
    )


def test_get_health_when_cowrie_pid_exists(
    client: tuple[TestClient, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_client, _ = client
    pid_path = tmp_path / "cowrie.pid"
    pid_path.write_text("12345", encoding="utf-8")
    monkeypatch.setenv("COWRIE_PID_PATH", str(pid_path))

    response = test_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "cowrie": "running"}


def test_get_health_when_cowrie_pid_missing(
    client: tuple[TestClient, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_client, _ = client
    missing_pid = tmp_path / "missing-cowrie.pid"
    monkeypatch.setenv("COWRIE_PID_PATH", str(missing_pid))

    response = test_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "cowrie": "stopped"}
