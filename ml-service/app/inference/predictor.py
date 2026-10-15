"""Random Forest inference on EMBER 2381-D feature vectors.

Probability semantics:
    ``probability`` in AnalyzeResponse is P(malicious | features), i.e.,
    the class-1 (malicious) probability from predict_proba(). It is NOT
    a certainty that the file is malware; it is the model's calibrated
    confidence given the extracted static PE features.

Feature explanations:
    The ``top_features`` list reports the globally most important RF
    features (by mean decrease in impurity) whose indices overlap with
    the largest absolute values in the extracted feature vector. This is
    a model-global heuristic, not a per-file Shapley value. Results are
    labelled "influential model features" to avoid overstating causality.
"""

from __future__ import annotations

import numpy as np

from app.model.model_loader import LoadedModel
from app.schemas import AnalyzeResponse, TopFeature

_FEATURE_GROUP_DESCRIPTIONS: dict[str, str] = {
    "histogram": "byte value distribution across the file",
    "byteentropy": "joint byte/entropy histogram (complexity indicator)",
    "strings": "printable string statistics (count, entropy, URLs, paths)",
    "general": "general PE file properties (size, imports, exports, TLS)",
    "header": "COFF and optional PE header fields (machine, subsystem, linker)",
    "section": "PE section names, sizes, entropies, and characteristics",
    "imports": "imported libraries and function names",
    "exports": "exported function names",
    "datadirectories": "PE data directory sizes and virtual addresses",
}

_FEATURE_GROUPS: list[tuple[str, int]] = [
    ("histogram", 256),
    ("byteentropy", 256),
    ("strings", 104),
    ("general", 10),
    ("header", 62),
    ("section", 255),
    ("imports", 1280),
    ("exports", 128),
    ("datadirectories", 30),
]


def _group_for_index(feature_idx: int) -> str:
    """Return the feature group name for a flat feature index."""
    offset = 0
    for name, dim in _FEATURE_GROUPS:
        if feature_idx < offset + dim:
            return name
        offset += dim
    return "unknown"


def _top_features(
    features: np.ndarray,
    loaded_model: LoadedModel,
    *,
    n: int = 5,
) -> list[TopFeature]:
    """Select up to *n* influential model features for this file.

    Method: rank all features by (global_importance * |feature_value|),
    then take the top-n. This is a fast, zero-dependency heuristic that
    highlights which globally important features are also active in this
    specific sample. It is NOT an exact per-file attribution (no SHAP).
    """
    estimator = loaded_model.estimator
    if estimator is None or not hasattr(estimator, "feature_importances_"):
        return []

    importances = np.asarray(estimator.feature_importances_, dtype=np.float64)
    feat_abs = np.abs(features.astype(np.float64))
    # Normalise feature magnitudes to [0,1] to avoid scale dominance
    feat_max = feat_abs.max()
    feat_norm = feat_abs / feat_max if feat_max > 0 else feat_abs
    score = importances * feat_norm

    top_indices = np.argsort(score)[::-1][:n]
    feature_names = loaded_model.feature_names

    result: list[TopFeature] = []
    for idx in top_indices:
        idx_int = int(idx)
        name = (
            feature_names[idx_int]
            if idx_int < len(feature_names)
            else f"feature_{idx_int}"
        )
        group = _group_for_index(idx_int)
        description = _FEATURE_GROUP_DESCRIPTIONS.get(group, "PE static feature")
        result.append(
            TopFeature(
                feature=name,
                importance=round(float(importances[idx_int]), 8),
                description=(
                    f"Influential model feature ({group}): {description}. "
                    "Note: importance reflects global RF training signal, "
                    "not a per-file causal explanation."
                ),
            )
        )
    return result


class ModelNotReadyError(RuntimeError):
    """Raised when inference is requested before a trained artifact is loaded."""


def predict(features: np.ndarray, loaded_model: LoadedModel) -> AnalyzeResponse:
    """Classify an EMBER 2381-D feature vector using the trained Random Forest.

    Args:
        features: float32 array of shape (2381,) from extract_ember_features().
        loaded_model: model loaded once at application startup.

    Returns:
        AnalyzeResponse with verdict, probability (P(malicious)), risk_score,
        and up to 5 influential feature labels.

    Raises:
        ModelNotReadyError: if the model artifact is not loaded.
        ValueError: if features has wrong shape.
    """
    if not loaded_model.ready or loaded_model.estimator is None:
        raise ModelNotReadyError(
            "Trained Random Forest artifact is not loaded. Train offline on "
            "EMBER 2018, save with Joblib, and set ML_MODEL_PATH."
        )

    estimator = loaded_model.estimator
    expected_n = int(getattr(estimator, "n_features_in_", -1))
    if features.ndim != 1 or features.shape[0] != expected_n:
        raise ValueError(
            f"Feature vector has shape {features.shape}; model expects ({expected_n},)."
        )

    # Reshape to (1, n_features) for sklearn
    X = np.ascontiguousarray(features, dtype=np.float32).reshape(1, -1)

    # Predict class and probabilities
    pred_label = int(estimator.predict(X)[0])
    proba_row = estimator.predict_proba(X)[0]  # shape (2,): [P(benign), P(malicious)]

    # Locate malicious class index (classes_ = [0, 1])
    classes = list(getattr(estimator, "classes_", [0, 1]))
    malicious_idx = classes.index(1) if 1 in classes else 1
    prob_malicious = float(np.clip(proba_row[malicious_idx], 0.0, 1.0))

    verdict: str = "malicious" if pred_label == 1 else "benign"
    risk_score: int = int(round(prob_malicious * 100))

    top_feats = _top_features(features, loaded_model, n=5)

    return AnalyzeResponse(
        verdict=verdict,  # type: ignore[arg-type]
        probability=prob_malicious,
        risk_score=risk_score,
        top_features=top_feats,
    )
