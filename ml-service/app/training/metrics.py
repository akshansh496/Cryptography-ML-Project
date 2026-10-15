"""Evaluation helpers for the offline EMBER Random Forest."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
from sklearn.base import ClassifierMixin
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass(frozen=True)
class EvaluationMetrics:
    """Test-set metrics computed after offline training."""

    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float | None
    confusion_matrix: list[list[int]]
    n_test_samples: int
    n_features: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_classifier(
    estimator: ClassifierMixin,
    X_test: np.ndarray,
    y_test: np.ndarray,
    *,
    batch_size: int = 4096,
) -> EvaluationMetrics:
    """Evaluate a fitted classifier on an untouched labeled test matrix.

    Large memmaps are scored in batches so evaluation does not copy the full
    200k × 2381 test matrix into RAM.
    """

    if X_test.shape[0] != y_test.shape[0]:
        raise ValueError(
            f"Test X/y row mismatch: X={X_test.shape[0]}, y={y_test.shape[0]}."
        )
    if X_test.shape[0] == 0:
        raise ValueError("Cannot evaluate on an empty test set.")

    n = int(X_test.shape[0])
    y_true = np.asarray(y_test)
    y_pred = np.empty(n, dtype=np.int32)
    scores = np.empty(n, dtype=np.float64)
    classes = list(getattr(estimator, "classes_", [0, 1]))
    malicious_index = classes.index(1) if 1 in classes else 1
    has_proba = hasattr(estimator, "predict_proba")

    for start in range(0, n, batch_size):
        end = min(start + batch_size, n)
        batch = np.ascontiguousarray(X_test[start:end])
        if has_proba:
            proba = estimator.predict_proba(batch)
            scores[start:end] = proba[:, malicious_index]
            y_pred[start:end] = estimator.classes_[np.argmax(proba, axis=1)]
        else:
            y_pred[start:end] = estimator.predict(batch)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc: float | None = None
    if has_proba:
        roc_auc = float(roc_auc_score(y_true, scores))

    return EvaluationMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        confusion_matrix=cm.astype(int).tolist(),
        n_test_samples=n,
        n_features=int(X_test.shape[1]),
    )


def format_evaluation_report(
    *,
    n_train_samples: int,
    metrics: EvaluationMetrics,
    target_accuracy: float = 0.95,
    target_fpr: float = 0.03,
) -> str:
    """Render a clear evaluation summary without claiming unmet targets."""

    roc_text = "n/a" if metrics.roc_auc is None else f"{metrics.roc_auc:.6f}"
    lines = [
        "========================================",
        "EMBER RANDOM FOREST EVALUATION",
        "========================================",
        "",
        f"Train samples: {n_train_samples}",
        f"Test samples: {metrics.n_test_samples}",
        f"Features: {metrics.n_features}",
        "",
        f"Accuracy: {metrics.accuracy:.6f}",
        f"Precision: {metrics.precision:.6f}",
        f"Recall: {metrics.recall:.6f}",
        f"F1: {metrics.f1:.6f}",
        f"False Positive Rate: {metrics.false_positive_rate:.6f}",
        f"False Negative Rate: {metrics.false_negative_rate:.6f}",
        f"ROC-AUC: {roc_text}",
        "",
        "Confusion Matrix [[TN, FP], [FN, TP]]:",
        f"{metrics.confusion_matrix}",
        "",
        f"PRD target accuracy >= {target_accuracy:.0%}: "
        f"{'MET' if metrics.accuracy >= target_accuracy else 'NOT MET'}",
        f"PRD target FPR <= {target_fpr:.0%}: "
        f"{'MET' if metrics.false_positive_rate <= target_fpr else 'NOT MET'}",
        "========================================",
    ]
    return "\n".join(lines)


def validate_feature_importances(
    importances: np.ndarray,
    *,
    n_features: int,
) -> None:
    """Validate Random Forest ``feature_importances_`` for later explainability."""

    values = np.asarray(importances, dtype=np.float64)
    if values.ndim != 1:
        raise ValueError(f"feature_importances_ must be 1-D, got shape {values.shape}.")
    if values.shape[0] != n_features:
        raise ValueError(
            f"feature_importances_ length {values.shape[0]} != n_features {n_features}."
        )
    if not np.isfinite(values).all():
        raise ValueError("feature_importances_ contains non-finite values.")
    if np.any(values < 0):
        raise ValueError("feature_importances_ contains negative values.")
    total = float(values.sum())
    if not np.isclose(total, 1.0, atol=1e-5):
        raise ValueError(
            f"feature_importances_ should sum approximately to 1.0, got {total}."
        )


def top_feature_importances(
    importances: np.ndarray,
    feature_names: list[str],
    *,
    limit: int = 20,
) -> list[tuple[int, str, float]]:
    """Return the top-N (index, name, importance) tuples for inspection."""

    values = np.asarray(importances, dtype=np.float64)
    order = np.argsort(values)[::-1][:limit]
    rows: list[tuple[int, str, float]] = []
    for idx in order:
        name = feature_names[int(idx)] if int(idx) < len(feature_names) else f"feature_{int(idx)}"
        rows.append((int(idx), name, float(values[int(idx)])))
    return rows
