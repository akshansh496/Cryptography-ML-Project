"""Unit tests for Random Forest training infrastructure.

These use small structural fixtures only. They do not train on the full EMBER
2018 corpus and must not be treated as a substitute for official training.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from app.data.ember_loader import EmberDatasetError
from app.model.model_loader import load_model
from app.training.rf_config import DEFAULT_RF_CONFIG, RandomForestConfig, build_random_forest, validate_rf_config
from app.training.trainer import MISSING_DATASET_TRAINING_MESSAGE, run_offline_training


def _write_vectorized_split(
    directory: Path,
    *,
    x_name: str,
    y_name: str,
    X: np.ndarray,
    y: np.ndarray,
) -> None:
    X.astype(np.float32).tofile(directory / x_name)
    y.astype(np.float32).tofile(directory / y_name)


def _tiny_ember_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    rng = np.random.default_rng(42)
    n_features = 8
    X_train = rng.normal(size=(40, n_features)).astype(np.float32)
    y_train = np.array([0, 1] * 20, dtype=np.float32)
    X_train[y_train == 1] += 1.5
    X_test = rng.normal(size=(12, n_features)).astype(np.float32)
    y_test = np.array([0, 1] * 6, dtype=np.float32)
    X_test[y_test == 1] += 1.5
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(data_dir, x_name="X_test.dat", y_name="y_test.dat", X=X_test, y=y_test)
    return data_dir


def test_random_forest_configuration_is_valid() -> None:
    validate_rf_config(DEFAULT_RF_CONFIG)
    assert DEFAULT_RF_CONFIG.n_estimators >= 1
    assert DEFAULT_RF_CONFIG.random_state == 42
    assert DEFAULT_RF_CONFIG.n_jobs == -1
    estimator = build_random_forest(DEFAULT_RF_CONFIG)
    assert isinstance(estimator, RandomForestClassifier)
    assert estimator.n_estimators == DEFAULT_RF_CONFIG.n_estimators
    assert estimator.random_state == 42


def test_invalid_rf_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="n_estimators"):
        validate_rf_config(RandomForestConfig(n_estimators=0))
    with pytest.raises(ValueError, match="n_jobs"):
        validate_rf_config(RandomForestConfig(n_jobs=0))


def test_small_fixture_trains_successfully(tmp_path: Path) -> None:
    data_dir = _tiny_ember_dir(tmp_path)
    model_path = tmp_path / "ember_rf.joblib"
    metadata_path = tmp_path / "ember_rf_metadata.json"
    config = RandomForestConfig(n_estimators=8, random_state=42, n_jobs=1)
    result = run_offline_training(
        data_dir=data_dir,
        model_path=model_path,
        metadata_path=metadata_path,
        config=config,
        require_official_dim=False,
        persist=True,
    )
    assert result.estimator.n_features_in_ == 8
    assert result.metrics.n_test_samples == 12
    assert result.model_path == model_path
    assert metadata_path.is_file()
    assert model_path.is_file()
    assert model_path.stat().st_size > 0


def test_predict_returns_binary_labels(tmp_path: Path) -> None:
    data_dir = _tiny_ember_dir(tmp_path)
    result = run_offline_training(
        data_dir=data_dir,
        model_path=tmp_path / "m.joblib",
        metadata_path=tmp_path / "m.json",
        config=RandomForestConfig(n_estimators=8, random_state=42, n_jobs=1),
        require_official_dim=False,
        persist=False,
    )
    preds = result.estimator.predict(result.dataset.test.X)
    assert set(np.unique(preds).tolist()).issubset({0, 1})
    assert preds.shape[0] == result.dataset.test.n_samples


def test_predict_proba_returns_valid_probabilities(tmp_path: Path) -> None:
    data_dir = _tiny_ember_dir(tmp_path)
    result = run_offline_training(
        data_dir=data_dir,
        model_path=tmp_path / "m.joblib",
        metadata_path=tmp_path / "m.json",
        config=RandomForestConfig(n_estimators=8, random_state=42, n_jobs=1),
        require_official_dim=False,
        persist=False,
    )
    proba = result.estimator.predict_proba(result.dataset.test.X)
    assert proba.shape == (result.dataset.test.n_samples, 2)
    assert np.all(proba >= 0.0) and np.all(proba <= 1.0)
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-6)


def test_feature_importances_dimension_and_finite(tmp_path: Path) -> None:
    data_dir = _tiny_ember_dir(tmp_path)
    result = run_offline_training(
        data_dir=data_dir,
        model_path=tmp_path / "m.joblib",
        metadata_path=tmp_path / "m.json",
        config=RandomForestConfig(n_estimators=8, random_state=42, n_jobs=1),
        require_official_dim=False,
        persist=False,
    )
    importances = result.estimator.feature_importances_
    assert importances.shape == (8,)
    assert np.isfinite(importances).all()
    assert np.all(importances >= 0.0)
    assert np.isclose(importances.sum(), 1.0, atol=1e-5)


def test_joblib_roundtrip_matches_predictions(tmp_path: Path) -> None:
    data_dir = _tiny_ember_dir(tmp_path)
    model_path = tmp_path / "ember_rf.joblib"
    metadata_path = tmp_path / "ember_rf_metadata.json"
    result = run_offline_training(
        data_dir=data_dir,
        model_path=model_path,
        metadata_path=metadata_path,
        config=RandomForestConfig(n_estimators=8, random_state=42, n_jobs=1),
        require_official_dim=False,
        persist=True,
    )
    X = result.dataset.test.X
    original = result.estimator.predict(X)
    loaded_blob = joblib.load(model_path)
    assert isinstance(loaded_blob, dict)
    restored = loaded_blob["estimator"]
    np.testing.assert_array_equal(restored.predict(X), original)

    # load_model correctly rejects this fixture (n_features_in_=8 ≠ 2381).
    # The joblib roundtrip is already verified above via restored.predict(X).
    # Verify the loader refuses the tiny model cleanly (no crash, ready=False).
    loaded = load_model(model_path)
    assert loaded.ready is False
    assert "2381" in loaded.load_error or "n_features" in loaded.load_error
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    for key in (
        "model_type",
        "feature_version",
        "n_features",
        "n_estimators",
        "random_state",
        "training_samples",
        "test_samples",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "false_positive_rate",
        "false_negative_rate",
        "trained_at",
    ):
        assert key in payload
    assert payload["training_samples"] == result.dataset.train.n_samples
    assert payload["test_samples"] == result.dataset.test.n_samples
    assert payload["accuracy"] == result.metrics.accuracy


def test_missing_dataset_does_not_write_joblib(tmp_path: Path) -> None:
    missing = tmp_path / "no-ember"
    model_path = tmp_path / "ember_rf.joblib"
    with pytest.raises(EmberDatasetError, match="EMBER 2018 dataset not found") as exc_info:
        run_offline_training(
            data_dir=missing,
            model_path=model_path,
            metadata_path=tmp_path / "meta.json",
            require_official_dim=False,
            persist=True,
        )
    assert str(exc_info.value) == MISSING_DATASET_TRAINING_MESSAGE
    assert not model_path.exists()
