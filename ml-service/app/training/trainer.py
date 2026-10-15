"""Offline Random Forest training for EMBER 2018.

This module is used only by training scripts. FastAPI must not import it on
the request path to fit a model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from app.config import ML_SERVICE_ROOT, get_settings
from app.data.ember_feature_schema import EMBER_FEATURE_DIM, SUPERVISED_LABELS
from app.data.ember_loader import EmberDataset, EmberDatasetError, EmberSplit, load_ember_dataset
from app.training.artifact import (
    build_model_artifact,
    build_training_metadata,
    save_model_artifact,
    save_training_metadata,
)
from app.training.metrics import (
    EvaluationMetrics,
    evaluate_classifier,
    format_evaluation_report,
    top_feature_importances,
    validate_feature_importances,
)
from app.training.rf_config import DEFAULT_RF_CONFIG, RandomForestConfig, build_random_forest, validate_rf_config

MISSING_DATASET_TRAINING_MESSAGE = (
    "EMBER 2018 dataset not found at ml-service/data/ember2018/. "
    "Place the official dataset there before training."
)

IMBALANCE_RATIO_THRESHOLD = 0.40


@dataclass(frozen=True)
class TrainingResult:
    """Outputs of one offline training run."""

    estimator: RandomForestClassifier
    config: RandomForestConfig
    dataset: EmberDataset
    metrics: EvaluationMetrics
    model_path: Path | None
    metadata_path: Path | None
    metadata: dict[str, Any]
    load_seconds: float
    train_seconds: float
    eval_seconds: float
    model_bytes: int
    class_weight_rationale: str
    top_importances: list[tuple[int, str, float]]


def _class_percentages(n_benign: int, n_malicious: int) -> tuple[float, float]:
    total = n_benign + n_malicious
    if total == 0:
        return 0.0, 0.0
    return 100.0 * n_benign / total, 100.0 * n_malicious / total


def assess_class_weight(train: EmberSplit) -> tuple[str | None, str]:
    """Decide whether class_weight is justified from the actual train split.

    Official EMBER 2018 labeled training is designed to be balanced. Weighting
    is not applied automatically. A large imbalance (minority/majority below
    ``IMBALANCE_RATIO_THRESHOLD``) is reported but still does not silently
    change the estimator unless the caller sets ``class_weight`` explicitly.
    """

    n_benign = train.n_benign
    n_malicious = train.n_malicious
    minority = min(n_benign, n_malicious)
    majority = max(n_benign, n_malicious)
    ratio = float(minority) / float(majority) if majority else 0.0
    if ratio >= IMBALANCE_RATIO_THRESHOLD:
        return (
            None,
            "class_weight=None because the labeled training split is not "
            f"significantly imbalanced (benign={n_benign}, malicious={n_malicious}, "
            f"minority/majority={ratio:.3f}).",
        )
    return (
        None,
        "Labeled training split is imbalanced "
        f"(benign={n_benign}, malicious={n_malicious}, minority/majority={ratio:.3f}). "
        "class_weight remains None: weighting is not applied automatically, "
        "and the official test distribution is never modified.",
    )


def validate_supervised_split(
    split: EmberSplit,
    *,
    split_name: str,
    require_official_dim: bool,
) -> None:
    """Confirm a split is sklearn-ready for binary EMBER classification."""

    if split.X.shape[0] != split.y.shape[0]:
        raise EmberDatasetError(
            f"{split_name} features and labels have mismatched row counts: "
            f"X={split.X.shape[0]}, y={split.y.shape[0]}."
        )
    if require_official_dim and split.X.shape[1] != EMBER_FEATURE_DIM:
        raise EmberDatasetError(
            f"{split_name} has {split.X.shape[1]} features; official EMBER 2018 "
            f"feature_version=2 requires {EMBER_FEATURE_DIM}."
        )
    labels = set(int(v) for v in np.unique(split.y))
    if labels != set(SUPERVISED_LABELS):
        raise EmberDatasetError(
            f"{split_name} labels must be exactly {{0, 1}}, found {sorted(labels)}."
        )
    if split.n_benign == 0 or split.n_malicious == 0:
        raise EmberDatasetError(
            f"{split_name} must contain both classes; "
            f"benign={split.n_benign}, malicious={split.n_malicious}."
        )


def print_split_statistics(split: EmberSplit, *, split_name: str) -> None:
    pct_benign, pct_malicious = _class_percentages(split.n_benign, split.n_malicious)
    print(f"-- {split_name} --")
    print(f"  samples: {split.n_samples}")
    print(f"  features: {split.n_features}")
    print(f"  benign: {split.n_benign} ({pct_benign:.2f}%)")
    print(f"  malicious: {split.n_malicious} ({pct_malicious:.2f}%)")
    print(f"  unlabeled removed: {split.n_unlabeled_removed}")
    print(f"  labels: {sorted({int(v) for v in np.unique(split.y)})}")


# Fit sklearn RF in one shot when the dense matrix is small enough to copy.
_IN_CORE_BYTES = 1_200_000_000
# Per-tree bootstrap batch budget when training from memmap on small RAM.
_BOOTSTRAP_BYTES = 1_200_000_000


def _bootstrap_rows(n_samples: int, n_features: int) -> int:
    per_row = max(n_features, 1) * 4
    return int(min(n_samples, max(256, _BOOTSTRAP_BYTES // per_row)))


def fit_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    config: RandomForestConfig | None = None,
) -> tuple[RandomForestClassifier, float, dict[str, Any]]:
    """Fit RandomForestClassifier on labeled training data only.

    When X_train is larger than about 1.2 GiB (EMBER 600k × 2381 is ~5.7 GiB),
    sklearn's default ``fit`` would copy the full matrix and exhaust an 8 GiB
    machine. In that case each tree is trained on a bootstrap sample drawn
    **with replacement from the full training pool** (standard RF bagging with
    ``max_samples``), not on a reduced production dataset.
    """

    cfg = config or DEFAULT_RF_CONFIG
    validate_rf_config(cfg)
    y = np.asarray(y_train)
    n_samples, n_features = int(X_train.shape[0]), int(X_train.shape[1])
    matrix_bytes = n_samples * n_features * 4
    fit_info: dict[str, Any] = {
        "fit_mode": "in_core",
        "n_train_samples": n_samples,
        "bootstrap_rows": n_samples,
    }

    started = time.perf_counter()
    if matrix_bytes <= _IN_CORE_BYTES:
        estimator = build_random_forest(cfg)
        estimator.fit(np.ascontiguousarray(X_train), y)
        elapsed = time.perf_counter() - started
        return estimator, elapsed, fit_info

    n_bootstrap = _bootstrap_rows(n_samples, n_features)
    fit_info["fit_mode"] = "memmap_bootstrap"
    fit_info["bootstrap_rows"] = n_bootstrap
    print(
        f"Memory-safe Random Forest: {cfg.n_estimators} trees, each fit on "
        f"{n_bootstrap} bootstrap rows sampled with replacement from all "
        f"{n_samples} supervised training samples ({n_features} features)."
    )

    probe_n = min(256, n_samples)
    probe_idx = np.linspace(0, n_samples - 1, num=probe_n, dtype=np.int64)
    estimator = RandomForestClassifier(
        n_estimators=1,
        random_state=cfg.random_state,
        n_jobs=1,
        max_features=cfg.max_features,
        min_samples_split=cfg.min_samples_split,
        min_samples_leaf=cfg.min_samples_leaf,
        bootstrap=True,
        class_weight=cfg.class_weight,
    )
    estimator.fit(np.ascontiguousarray(X_train[probe_idx]), np.asarray(y[probe_idx]))

    trees: list[DecisionTreeClassifier] = []
    rng = np.random.RandomState(cfg.random_state)
    for tree_i in range(cfg.n_estimators):
        idx = rng.randint(0, n_samples, size=n_bootstrap)
        X_boot = np.ascontiguousarray(X_train[idx])
        y_boot = np.ascontiguousarray(y[idx])
        tree = DecisionTreeClassifier(
            max_features=cfg.max_features,
            min_samples_split=cfg.min_samples_split,
            min_samples_leaf=cfg.min_samples_leaf,
            random_state=cfg.random_state + tree_i,
            class_weight=cfg.class_weight,
        )
        tree.fit(X_boot, y_boot)
        trees.append(tree)
        del X_boot, y_boot
        if (tree_i + 1) % 10 == 0 or tree_i + 1 == cfg.n_estimators:
            print(f"  fitted tree {tree_i + 1}/{cfg.n_estimators}")

    estimator.estimators_ = trees
    estimator.n_estimators = cfg.n_estimators
    estimator.n_features_in_ = n_features
    elapsed = time.perf_counter() - started
    return estimator, elapsed, fit_info


def inference_sanity_check(
    estimator: RandomForestClassifier,
    X: np.ndarray,
    *,
    n_samples: int = 8,
) -> None:
    """Confirm predict / predict_proba on a few official test rows."""

    n = int(X.shape[0])
    take = min(n_samples, n)
    idx = np.linspace(0, n - 1, num=take, dtype=np.int64)
    batch = np.ascontiguousarray(X[idx])
    labels = estimator.predict(batch)
    proba = estimator.predict_proba(batch)
    if not set(np.unique(labels).tolist()).issubset({0, 1}):
        raise RuntimeError(f"Sanity check failed: unexpected labels {np.unique(labels)}.")
    if proba.shape != (take, 2):
        raise RuntimeError(f"Sanity check failed: predict_proba shape {proba.shape}.")
    if np.any(proba < 0.0) or np.any(proba > 1.0):
        raise RuntimeError("Sanity check failed: probabilities outside [0, 1].")
    if not np.allclose(proba.sum(axis=1), 1.0, atol=1e-6):
        raise RuntimeError("Sanity check failed: probability rows do not sum to 1.")
    if int(getattr(estimator, "n_features_in_", -1)) != int(X.shape[1]):
        raise RuntimeError(
            f"Sanity check failed: n_features_in_={estimator.n_features_in_} "
            f"vs X.shape[1]={X.shape[1]}."
        )
    print(
        f"Inference sanity check passed on {take} test rows "
        f"(n_features_in_={estimator.n_features_in_})."
    )


def run_offline_training(
    *,
    data_dir: Path | str | None = None,
    model_path: Path | None = None,
    metadata_path: Path | None = None,
    config: RandomForestConfig | None = None,
    require_official_dim: bool = True,
    persist: bool = True,
) -> TrainingResult:
    """Load EMBER, train RF on train only, evaluate on the official test split.

    Does not write a Joblib file unless training and evaluation succeed.
    """

    cfg = config or DEFAULT_RF_CONFIG
    validate_rf_config(cfg)
    settings = get_settings()
    resolved_model = Path(model_path) if model_path is not None else settings.resolved_model_path
    resolved_metadata = (
        Path(metadata_path)
        if metadata_path is not None
        else resolved_model.with_name("ember_rf_metadata.json")
    )

    load_started = time.perf_counter()
    try:
        dataset = load_ember_dataset(
            data_dir,
            require_test=True,
            require_official_dim=require_official_dim,
        )
    except EmberDatasetError as exc:
        message = str(exc)
        if "not found" in message.lower():
            raise EmberDatasetError(MISSING_DATASET_TRAINING_MESSAGE) from exc
        raise
    load_seconds = time.perf_counter() - load_started

    train = dataset.train
    test = dataset.test
    if test is None:
        raise EmberDatasetError(
            "Official EMBER test split is required for evaluation. "
            "Place test_features.jsonl or X_test.dat/y_test.dat under "
            "ml-service/data/ember2018/."
        )

    validate_supervised_split(train, split_name="train", require_official_dim=require_official_dim)
    validate_supervised_split(test, split_name="test", require_official_dim=require_official_dim)

    _, class_weight_rationale = assess_class_weight(train)
    if cfg.class_weight is not None:
        class_weight_rationale = (
            f"class_weight={cfg.class_weight!r} was set explicitly. {class_weight_rationale}"
        )

    print("Random Forest configuration:")
    print(f"  {cfg.to_sklearn_kwargs()}")
    print()
    print_split_statistics(train, split_name="train")
    print_split_statistics(test, split_name="test (untouched until evaluation)")
    print(f"  labeled test samples used: {test.n_samples}")
    print()
    print(class_weight_rationale)
    print()
    print("Fitting RandomForestClassifier on X_train/y_train only...")

    estimator, train_seconds, fit_info = fit_random_forest(train.X, train.y, cfg)
    print(f"Training time: {train_seconds:.3f}s")
    print(f"  fit_mode={fit_info['fit_mode']} bootstrap_rows={fit_info['bootstrap_rows']}")

    eval_started = time.perf_counter()
    metrics = evaluate_classifier(estimator, test.X, test.y)
    eval_seconds = time.perf_counter() - eval_started
    print(f"Evaluation time: {eval_seconds:.3f}s")
    print()
    print(format_evaluation_report(n_train_samples=train.n_samples, metrics=metrics))

    inference_sanity_check(estimator, test.X, n_samples=8)
    if int(estimator.n_features_in_) != int(train.n_features):
        raise EmberDatasetError(
            f"Trained model n_features_in_={estimator.n_features_in_} "
            f"does not match training features {train.n_features}."
        )

    importances = np.asarray(estimator.feature_importances_, dtype=np.float64)
    validate_feature_importances(importances, n_features=train.n_features)
    top_rows = top_feature_importances(importances, train.feature_names, limit=20)
    print()
    print("Top 20 feature importances (index, name, importance):")
    for idx, name, value in top_rows:
        print(f"  {idx:4d}  {name:24s}  {value:.8f}")

    saved_model: Path | None = None
    saved_metadata: Path | None = None
    model_bytes = 0
    artifact = build_model_artifact(
        estimator,
        feature_names=list(train.feature_names),
        config=cfg,
        metrics=metrics,
    )
    if persist:
        saved_model = save_model_artifact(artifact, resolved_model)
        model_bytes = saved_model.stat().st_size

    metadata = build_training_metadata(
        config=cfg,
        feature_count=train.n_features,
        train_sample_count=train.n_samples,
        test_sample_count=test.n_samples,
        metrics=metrics,
        model_path=saved_model or resolved_model,
        load_seconds=load_seconds,
        train_seconds=train_seconds,
        eval_seconds=eval_seconds,
        class_weight_rationale=class_weight_rationale,
    )
    metadata["dataset_format"] = dataset.format
    metadata["data_dir"] = str(dataset.data_dir)
    metadata["model_bytes"] = model_bytes
    metadata["unlabeled_removed_train"] = train.n_unlabeled_removed
    metadata["unlabeled_removed_test"] = test.n_unlabeled_removed
    metadata["fit_mode"] = fit_info["fit_mode"]
    metadata["bootstrap_rows"] = fit_info["bootstrap_rows"]
    if persist:
        saved_metadata = save_training_metadata(metadata, resolved_metadata)

    print()
    print("Performance")
    print(f"  dataset loading time: {load_seconds:.3f}s")
    print(f"  model training time: {train_seconds:.3f}s")
    print(f"  evaluation time: {eval_seconds:.3f}s")
    if persist and saved_model is not None:
        print(f"  model file size: {model_bytes} bytes ({model_bytes / (1024 * 1024):.2f} MiB)")
        print(f"  model artifact: {saved_model}")
        print(f"  metadata: {saved_metadata}")
    else:
        print("  model artifact not written (persist=False)")

    return TrainingResult(
        estimator=estimator,
        config=cfg,
        dataset=dataset,
        metrics=metrics,
        model_path=saved_model,
        metadata_path=saved_metadata,
        metadata=metadata,
        load_seconds=load_seconds,
        train_seconds=train_seconds,
        eval_seconds=eval_seconds,
        model_bytes=model_bytes,
        class_weight_rationale=class_weight_rationale,
        top_importances=top_rows,
    )


def default_artifact_paths() -> tuple[Path, Path]:
    """Return default Joblib and metadata paths under ml-service/models/."""

    model_path = get_settings().resolved_model_path
    metadata_path = ML_SERVICE_ROOT / "models" / "ember_rf_metadata.json"
    return model_path, metadata_path
