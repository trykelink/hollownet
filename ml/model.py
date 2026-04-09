"""Isolation Forest wrapper for Hollownet anomaly scoring."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

MIN_TRAINING_EVENTS = 50
# Normalized anomaly score threshold above which an event counts as anomalous in reports.
ANOMALY_ALERT_THRESHOLD = 70.0


class AnomalyDetector:
    """Train and score event anomalies with Isolation Forest."""

    def __init__(self) -> None:
        self._model: IsolationForest | None = None

    def train(self, df: pd.DataFrame) -> None:
        """Train the anomaly detector on the provided feature matrix."""

        if len(df) < MIN_TRAINING_EVENTS:
            raise ValueError("Datos insuficientes para análisis ML (mínimo 50 eventos)")

        self._model = IsolationForest(
            contamination=0.05,
            random_state=42,
        )
        self._model.fit(df)

    def score(self, df: pd.DataFrame) -> pd.Series:
        """Return normalized anomaly scores from 0 to 100 for each event."""

        if self._model is None:
            raise ValueError("AnomalyDetector must be trained or loaded before scoring")

        raw_scores = pd.Series(-self._model.score_samples(df), index=df.index, dtype="float64")
        minimum = float(raw_scores.min())
        maximum = float(raw_scores.max())

        if maximum == minimum:
            return pd.Series(0.0, index=df.index, dtype="float64")

        normalized = ((raw_scores - minimum) / (maximum - minimum)) * 100.0
        return normalized.clip(lower=0.0, upper=100.0)

    def save(self, path: str) -> None:
        """Persist the trained model to disk with joblib."""

        if self._model is None:
            raise ValueError("AnomalyDetector must be trained before saving")

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, destination)

    def load(self, path: str) -> None:
        """Load a trained model from disk."""

        self._model = joblib.load(path)
