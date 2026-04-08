"""Tests for the anomaly detection model."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ml.model import AnomalyDetector


def test_train_raises_for_small_datasets() -> None:
    detector = AnomalyDetector()
    frame = pd.DataFrame(np.random.rand(49, 8))

    with pytest.raises(ValueError, match="mínimo 50 eventos"):
        detector.train(frame)


def test_train_accepts_datasets_with_fifty_or_more_events() -> None:
    detector = AnomalyDetector()
    frame = pd.DataFrame(np.random.rand(50, 8))

    detector.train(frame)


def test_score_returns_values_between_zero_and_one_hundred() -> None:
    detector = AnomalyDetector()
    frame = pd.DataFrame(np.random.rand(80, 8))
    detector.train(frame)

    scores = detector.score(frame)

    assert len(scores) == 80
    assert scores.between(0, 100).all()
