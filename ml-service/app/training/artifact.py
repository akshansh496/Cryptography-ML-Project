"""Joblib artifact + metadata persistence for the offline-trained EMBER RF."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier

from app.data.ember_feature_schema import EMBER_FEATURE_VERSION
from app.training.metrics import EvaluationMetrics
from app.training.rf_config import (
    DATASET_NAME,
    MODEL_NAME,
    MODEL_VERSION,
    RandomForestConfig,
)

ARTIFACT_ESTIMATOR_KEY = "estimator"
ARTIFACT_FEATURE_NAMES_KEY = "feature_names"
ARTIFACT_FEATURE_DIM_KEY = "feature_dim"
ARTIFACT_FEATURE_VERSION_KEY = "ember_feature_version"
ARTIFACT_MODEL_NAME_KEY = "model_name"
ARTIFACT_MODEL_VERSION_KEY = "model_version"
ARTIFACT_CONFIG_KEY = "rf_config"
ARTIFACT_METRICS_KEY = "metrics"


def build_model_artifact(
    estimator: RandomForestClassifier,
    *,
    feature_names: list[str],
    config: RandomForestConfig,
    metrics: EvaluationMetrics | None = None,
) -> dict[str, Any]:
    """Bundle estimator + schema/metadata for FastAPI ``load_model`` compatibility."""

    artifact: dict[str, Any] = {
        ARTIFACT_ESTIMATOR_KEY: estimator,
        ARTIFACT_FEATURE_NAMES_KEY: list(feature_names),
        ARTIFACT_FEATURE_DIM_KEY: int(len(feature_names)),
        ARTIFACT_FEATURE_VERSION_KEY: EMBER_FEATURE_VERSION,
        ARTIFACT_MODEL_NAME_KEY: MODEL_NAME,
        ARTIFACT_MODEL_VERSION_KEY: MODEL_VERSION,
        ARTIFACT_CONFIG_KEY: config.to_metadata(),
    }
    if metrics is not None:
        artifact[ARTIFACT_METRICS_KEY] = metrics.to_dict()
    return artifact


def save_model_artifact(artifact: dict[str, Any], model_path: Path) -> Path:
    """Serialize the training artifact with Joblib."""

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)
    return model_path


def build_training_metadata(
    *,
    config: RandomForestConfig,
    feature_count: int,
    train_sample_count: int,
    test_sample_count: int,
    metrics: EvaluationMetrics,
    model_path: Path,
    load_seconds: float,
    train_seconds: float,
    eval_seconds: float,
    class_weight_rationale: str,
) -> dict[str, Any]:
    """Create JSON-serializable metadata from the actual training run."""

    return {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "dataset_name": DATASET_NAME,
        "ember_feature_version": EMBER_FEATURE_VERSION,
        "feature_count": int(feature_count),
        "training_sample_count": int(train_sample_count),
        "test_sample_count": int(test_sample_count),
        "random_state": config.random_state,
        "n_estimators": config.n_estimators,
        "n_jobs": config.n_jobs,
        "max_features": config.max_features,
        "min_samples_split": config.min_samples_split,
        "min_samples_leaf": config.min_samples_leaf,
        "bootstrap": config.bootstrap,
        "class_weight": config.class_weight,
        "class_weight_rationale": class_weight_rationale,
        "model_type": "RandomForestClassifier",
        "feature_version": EMBER_FEATURE_VERSION,
        "n_features": int(feature_count),
        "training_samples": int(train_sample_count),
        "test_samples": int(test_sample_count),
        "accuracy": metrics.accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "false_positive_rate": metrics.false_positive_rate,
        "false_negative_rate": metrics.false_negative_rate,
        "roc_auc": metrics.roc_auc,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "confusion_matrix": metrics.confusion_matrix,
        "model_path": str(model_path),
        "timings_seconds": {
            "dataset_loading": load_seconds,
            "training": train_seconds,
            "evaluation": eval_seconds,
        },
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
    }


def save_training_metadata(metadata: dict[str, Any], metadata_path: Path) -> Path:
    """Write training/evaluation metadata as UTF-8 JSON."""

    metadata_path = Path(metadata_path)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata_path
