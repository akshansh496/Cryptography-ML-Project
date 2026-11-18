"""Reproducible Random Forest configuration for EMBER 2018 offline training.

Why this configuration:
- ``n_estimators=100``: enough trees for a stable majority vote on a 2381-D
  static feature space without making local training impractically slow on
  ~600k labeled EMBER rows.
- ``max_features="sqrt"``: sklearn classification default; reduces tree
  correlation in a high-dimensional hashed/histogram feature space.
- ``min_samples_leaf=1`` / ``min_samples_split=2``: allow full leaves; EMBER's
  labeled train split is large enough that extreme memorization risk is lower
  than with tiny datasets.
- ``bootstrap=True``: standard bagging for RF variance reduction.
- ``random_state=42``: deterministic bootstrap/feature sampling.
- ``n_jobs=-1``: use all local CPUs for fit/predict.
- ``class_weight=None``: official EMBER 2018 labeled train is balanced
  (benign≈malicious). Class weighting is not enabled by default; enable only
  after inspecting a real imbalance and documenting the impact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sklearn.ensemble import RandomForestClassifier

MODEL_NAME = "ember_rf"
MODEL_VERSION = "1.0.0"
DATASET_NAME = "EMBER 2018"


@dataclass(frozen=True)
class RandomForestConfig:
    """Explicit Random Forest hyperparameters used for offline training."""

    n_estimators: int = 100
    random_state: int = 42
    n_jobs: int = -1
    max_features: str | int | float = "sqrt"
    min_samples_split: int = 2
    min_samples_leaf: int = 1
    bootstrap: bool = True
    class_weight: str | dict[str, float] | None = None
    # Keep None unless a documented imbalance assessment justifies weighting.
    oob_score: bool = False

    def to_sklearn_kwargs(self) -> dict[str, Any]:
        return {
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
            "max_features": self.max_features,
            "min_samples_split": self.min_samples_split,
            "min_samples_leaf": self.min_samples_leaf,
            "bootstrap": self.bootstrap,
            "class_weight": self.class_weight,
            "oob_score": self.oob_score,
        }

    def to_metadata(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_RF_CONFIG = RandomForestConfig()


def build_random_forest(config: RandomForestConfig | None = None) -> RandomForestClassifier:
    """Construct an unfitted RandomForestClassifier with the project defaults."""

    cfg = config or DEFAULT_RF_CONFIG
    return RandomForestClassifier(**cfg.to_sklearn_kwargs())


def validate_rf_config(config: RandomForestConfig) -> None:
    """Raise ``ValueError`` when the configuration is invalid."""

    if config.n_estimators < 1:
        raise ValueError(f"n_estimators must be >= 1, got {config.n_estimators}.")
    if config.n_jobs == 0:
        raise ValueError("n_jobs cannot be 0.")
    if config.min_samples_split < 2:
        raise ValueError("min_samples_split must be >= 2.")
    if config.min_samples_leaf < 1:
        raise ValueError("min_samples_leaf must be >= 1.")
    if config.random_state is None:
        raise ValueError("random_state must be set for reproducibility.")
