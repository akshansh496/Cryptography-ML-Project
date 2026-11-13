"""Load and validate the EMBER Random Forest artifact once at startup.

The Joblib artifact is a dict:
  {
    "estimator": RandomForestClassifier,
    "feature_names": [...],
    "feature_dim": 2381,
    "ember_feature_version": 2,
    ...
  }

Validation at load time:
  - estimator.n_features_in_ == 2381
  - estimator.classes_ == {0, 1}

A missing or invalid artifact does NOT crash the process: ``ready=False``
is set and the /health endpoint continues to respond. The /internal/analyze
endpoint raises ModelNotReadyError (503) until a valid artifact is present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.data.ember_feature_schema import EMBER_FEATURE_DIM

logger = logging.getLogger(__name__)

_EXPECTED_CLASSES = {0, 1}


@dataclass
class LoadedModel:
    """Container for the offline-trained classifier loaded once at process start."""

    estimator: Any | None = None
    feature_names: list[str] = field(default_factory=list)
    path: Path | None = None
    ready: bool = False
    load_error: str = ""


def _validate_estimator(estimator: Any, path: Path) -> str | None:
    """Return an error string if the estimator fails validation, else None."""
    n_features = getattr(estimator, "n_features_in_", None)
    if n_features is None:
        return f"estimator has no n_features_in_ attribute ({path})"
    if int(n_features) != EMBER_FEATURE_DIM:
        return (
            f"estimator.n_features_in_={n_features} but EMBER feature_version=2 "
            f"requires {EMBER_FEATURE_DIM} ({path})"
        )
    classes = set(int(c) for c in getattr(estimator, "classes_", []))
    if classes != _EXPECTED_CLASSES:
        return (
            f"estimator.classes_={sorted(classes)} — expected {{0, 1}} ({path})"
        )
    if not hasattr(estimator, "predict") or not hasattr(estimator, "predict_proba"):
        return f"estimator missing predict/predict_proba ({path})"
    return None


def load_model(model_path: Path) -> LoadedModel:
    """Load and validate a Joblib-serialized Random Forest.

    Missing or invalid artifacts return LoadedModel(ready=False) rather than
    raising — the FastAPI lifespan hook must not crash on a cold start.
    """
    if not model_path.exists() or not model_path.is_file():
        msg = (
            f"ML model artifact not found at {model_path}. "
            "Run scripts/train_ember_rf.py to produce it. "
            "Inference will remain unavailable until the artifact is present."
        )
        logger.warning(msg)
        return LoadedModel(path=model_path, ready=False, load_error=msg)

    try:
        artifact = joblib.load(model_path)
    except Exception as exc:
        msg = f"Failed to load Joblib artifact at {model_path}: {exc}"
        logger.error(msg)
        return LoadedModel(path=model_path, ready=False, load_error=msg)

    # Unwrap the artifact dict (training always writes a dict with "estimator" key)
    if isinstance(artifact, dict) and "estimator" in artifact:
        estimator = artifact["estimator"]
        feature_names = list(
            artifact.get("feature_names")
            or getattr(estimator, "feature_names_in_", [])
            or []
        )
    elif hasattr(artifact, "predict_proba"):
        # Bare estimator — accept but warn
        estimator = artifact
        feature_names = list(getattr(estimator, "feature_names_in_", []) or [])
        logger.warning(
            "Loaded a bare estimator from %s (expected a dict artifact). "
            "Feature names may be unavailable.",
            model_path,
        )
    else:
        msg = f"Unrecognized Joblib artifact at {model_path} (type={type(artifact).__name__})"
        logger.error(msg)
        return LoadedModel(path=model_path, ready=False, load_error=msg)

    # Validate the estimator
    error = _validate_estimator(estimator, model_path)
    if error:
        logger.error("Model validation failed: %s", error)
        return LoadedModel(path=model_path, ready=False, load_error=error)

    logger.info(
        "Loaded ML model from %s (n_features_in_=%d, n_estimators=%d)",
        model_path,
        estimator.n_features_in_,
        getattr(estimator, "n_estimators", "?"),
    )
    return LoadedModel(
        estimator=estimator,
        feature_names=feature_names,
        path=model_path,
        ready=True,
        load_error="",
    )
