"""Feature extraction utilities for Hollownet anomaly detection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

FEATURE_COLUMNS = [
    "hour_of_day",
    "is_weekend",
    "session_duration",
    "attempts_per_ip",
    "unique_passwords",
    "unique_usernames",
    "has_command",
    "is_login_success",
]


def extract_features(events: list[dict[str, Any]]) -> pd.DataFrame:
    """Transform raw event dictionaries into model-ready numeric features."""

    if not events:
        empty_frame = pd.DataFrame(columns=FEATURE_COLUMNS)
        empty_frame.index = pd.Index([], name="event_id")
        return empty_frame

    events_frame = pd.DataFrame(events).copy()
    events_frame["timestamp"] = pd.to_datetime(events_frame["timestamp"], utc=True)
    events_frame["username"] = events_frame.get("username")
    events_frame["password"] = events_frame.get("password")
    events_frame["command"] = events_frame.get("command")
    events_frame["eventid"] = events_frame.get("eventid")
    events_frame = events_frame.sort_values("timestamp").reset_index(drop=True)

    session_spans = events_frame.groupby("session")["timestamp"].agg(["min", "max"])
    session_durations = (session_spans["max"] - session_spans["min"]).dt.total_seconds()
    password_counts = events_frame.groupby("src_ip")["password"].nunique(dropna=True)
    username_counts = events_frame.groupby("src_ip")["username"].nunique(dropna=True)
    attempts_per_ip = _calculate_attempts_per_ip(events_frame)

    feature_frame = pd.DataFrame(
        {
            "event_id": events_frame["event_id"].to_numpy(),
            "hour_of_day": events_frame["timestamp"].dt.hour.astype(int).to_numpy(),
            "is_weekend": (events_frame["timestamp"].dt.dayofweek >= 5).astype(int).to_numpy(),
            "session_duration": (
                events_frame["session"].map(session_durations).fillna(0).astype(float).to_numpy()
            ),
            "attempts_per_ip": attempts_per_ip.astype(int).to_numpy(),
            "unique_passwords": (
                events_frame["src_ip"].map(password_counts).fillna(0).astype(int).to_numpy()
            ),
            "unique_usernames": (
                events_frame["src_ip"].map(username_counts).fillna(0).astype(int).to_numpy()
            ),
            "has_command": (
                events_frame["command"].fillna("").astype(str).str.strip().ne("").astype(int).to_numpy()
            ),
            "is_login_success": events_frame["eventid"].eq("cowrie.login.success").astype(int).to_numpy(),
        }
    )
    feature_frame = feature_frame.set_index("event_id")
    feature_frame.index.name = "event_id"
    return feature_frame[FEATURE_COLUMNS]


def _calculate_attempts_per_ip(events_frame: pd.DataFrame) -> pd.Series:
    attempts = pd.Series(index=events_frame.index, dtype="int64")
    window = pd.Timedelta(hours=24)
    grouped_indexes: dict[str, list[int]] = defaultdict(list)

    for row_index, src_ip in events_frame["src_ip"].items():
        grouped_indexes[str(src_ip)].append(row_index)

    for row_indexes in grouped_indexes.values():
        left = 0
        timestamps = events_frame.loc[row_indexes, "timestamp"].tolist()
        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window:
                left += 1
            attempts.iloc[row_indexes[right]] = right - left + 1

    return attempts.sort_index()
