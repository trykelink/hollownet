"""Tests for ML PostgreSQL helpers."""

from __future__ import annotations

from unittest.mock import Mock

from ml.database import create_tables, get_events, update_anomaly_scores


def test_create_tables_executes_create_statement() -> None:
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=None)
    conn = Mock()
    conn.cursor.return_value = cursor

    create_tables(conn)

    conn.cursor.assert_called_once_with()
    executed_sql = cursor.execute.call_args.args[0]
    assert "CREATE TABLE IF NOT EXISTS anomaly_scores" in executed_sql
    conn.commit.assert_called_once_with()


def test_get_events_returns_rows_as_plain_dicts() -> None:
    rows = [
        {
            "event_id": "event-1",
            "session": "session-1",
            "src_ip": "203.0.113.10",
            "timestamp": "2026-04-08T12:00:00Z",
            "username": "root",
            "password": "admin",
            "command": None,
            "protocol": "ssh",
            "raw": {"eventid": "cowrie.login.failed"},
            "eventid": "cowrie.login.failed",
            "country": "AR",
        }
    ]
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=None)
    cursor.fetchall.return_value = rows
    conn = Mock()
    conn.cursor.return_value = cursor

    events = get_events(conn)

    assert events == rows
    assert set(events[0]) == {
        "event_id",
        "session",
        "src_ip",
        "timestamp",
        "username",
        "password",
        "command",
        "protocol",
        "raw",
        "eventid",
        "country",
    }


def test_get_events_passes_hours_parameter_to_query() -> None:
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=None)
    cursor.fetchall.return_value = []
    conn = Mock()
    conn.cursor.return_value = cursor

    get_events(conn, hours=24)

    execute_args = cursor.execute.call_args.args
    assert "INTERVAL '1 hour'" in execute_args[0]
    assert execute_args[1] == (24,)


def test_update_anomaly_scores_upserts_each_score() -> None:
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=None)
    conn = Mock()
    conn.cursor.return_value = cursor
    scores = {"event-1": 91.5, "event-2": 12.0}

    update_anomaly_scores(conn, scores)

    executed_sql = cursor.executemany.call_args.args[0]
    rows = cursor.executemany.call_args.args[1]
    assert "ON CONFLICT (event_id) DO UPDATE" in executed_sql
    assert rows == [("event-1", 91.5), ("event-2", 12.0)]
    conn.commit.assert_called_once_with()


def test_update_anomaly_scores_handles_empty_dict() -> None:
    conn = Mock()

    update_anomaly_scores(conn, {})

    conn.cursor.assert_not_called()
    conn.commit.assert_not_called()
