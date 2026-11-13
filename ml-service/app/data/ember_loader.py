"""Reusable EMBER 2018 dataset loader for offline training.

Supports the official on-disk layouts:

1. Vectorized float32 memmaps produced by elastic/ember::
   ``X_train.dat``, ``y_train.dat``, ``X_test.dat``, ``y_test.dat``

2. Raw feature JSONL from the EMBER 2018 release::
   ``train_features_0.jsonl`` … ``train_features_5.jsonl``, ``test_features.jsonl``

Raw JSONL rows are vectorized with the official feature_version=2 schema
(2381 dimensions). Unlabeled samples (label == -1) are removed for supervised
use. Random Forest does not require scaling, so this module never applies
StandardScaler / MinMaxScaler / normalization beyond EMBER's own per-group
histogram normalizations inside the vectorizer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal

import numpy as np

from app.data.ember_feature_schema import (
    EMBER_FEATURE_DIM,
    EMBER_FEATURE_NAMES,
    LABEL_BENIGN,
    LABEL_MALICIOUS,
    LABEL_UNLABELED,
    SUPERVISED_LABELS,
)
from app.data.ember_vectorizer import vectorize_raw_features

DatasetFormat = Literal["vectorized", "jsonl"]

TRAIN_JSONL_NAMES = tuple(f"train_features_{i}.jsonl" for i in range(6))
TEST_JSONL_NAME = "test_features.jsonl"
VECTORIZED_TRAIN_X = "X_train.dat"
VECTORIZED_TRAIN_Y = "y_train.dat"
VECTORIZED_TEST_X = "X_test.dat"
VECTORIZED_TEST_Y = "y_test.dat"

MISSING_DATASET_MESSAGE = (
    "EMBER 2018 dataset not found. Place the extracted dataset under "
    "ml-service/data/ember2018/."
)


class EmberDatasetError(ValueError):
    """Raised when the EMBER dataset is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class EmberSplit:
    """One supervised EMBER split ready for scikit-learn."""

    X: np.ndarray
    y: np.ndarray
    feature_names: list[str]
    n_raw_samples: int
    n_unlabeled_removed: int
    n_benign: int
    n_malicious: int

    @property
    def n_samples(self) -> int:
        return int(self.X.shape[0])

    @property
    def n_features(self) -> int:
        return int(self.X.shape[1]) if self.X.ndim == 2 else 0


@dataclass(frozen=True)
class EmberDataset:
    """Train (+ optional test) matrices with shared feature ordering."""

    train: EmberSplit
    test: EmberSplit | None
    data_dir: Path
    format: DatasetFormat
    feature_names: list[str]


@dataclass(frozen=True)
class EmberDatasetInfo:
    """Summary statistics for inspection scripts (no full matrix dump)."""

    data_dir: Path
    format: DatasetFormat | None
    dataset_present: bool
    n_train_samples: int
    n_test_samples: int
    n_features: int
    n_train_benign: int
    n_train_malicious: int
    n_test_benign: int
    n_test_malicious: int
    n_train_unlabeled: int
    n_test_unlabeled: int
    feature_names: list[str]
    missing_value_counts: dict[str, int]
    notes: list[str]


def resolve_ember_data_dir(data_dir: Path | str | None = None) -> Path:
    """Resolve the EMBER data directory, defaulting to ``ml-service/data/ember2018``."""

    if data_dir is None:
        from app.config import get_settings

        return get_settings().resolved_ember_data_dir
    return Path(data_dir).expanduser().resolve()


def ensure_ember_dataset_present(data_dir: Path | str | None = None) -> Path:
    """Return the data directory or raise a clear actionable error if missing."""

    path = resolve_ember_data_dir(data_dir)
    if not path.exists() or not path.is_dir():
        raise EmberDatasetError(MISSING_DATASET_MESSAGE)
    return path


def detect_ember_format(data_dir: Path | str | None = None) -> DatasetFormat:
    """Detect whether vectorized ``.dat`` files or raw JSONL files are present."""

    path = ensure_ember_dataset_present(data_dir)
    has_vectorized = all(
        (path / name).is_file()
        for name in (VECTORIZED_TRAIN_X, VECTORIZED_TRAIN_Y, VECTORIZED_TEST_X, VECTORIZED_TEST_Y)
    )
    # Allow train-only vectorized layouts during early inspection.
    has_vectorized_train = (path / VECTORIZED_TRAIN_X).is_file() and (path / VECTORIZED_TRAIN_Y).is_file()
    has_jsonl_train = any((path / name).is_file() for name in TRAIN_JSONL_NAMES)

    if has_vectorized or has_vectorized_train:
        return "vectorized"
    if has_jsonl_train:
        return "jsonl"
    raise EmberDatasetError(
        "EMBER 2018 dataset files not found under "
        f"{path}. Expected either vectorized files "
        f"({VECTORIZED_TRAIN_X}, {VECTORIZED_TRAIN_Y}, "
        f"{VECTORIZED_TEST_X}, {VECTORIZED_TEST_Y}) "
        f"or raw JSONL files ({TRAIN_JSONL_NAMES[0]} … {TRAIN_JSONL_NAMES[-1]}, "
        f"{TEST_JSONL_NAME})."
    )


def _read_jsonl_paths(paths: list[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    obj = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise EmberDatasetError(
                        f"Malformed JSONL in {path} at line {line_number}: {exc}"
                    ) from exc
                if not isinstance(obj, dict):
                    raise EmberDatasetError(
                        f"Malformed EMBER sample in {path} at line {line_number}: "
                        "expected a JSON object."
                    )
                yield obj


def _locate_train_jsonl(data_dir: Path) -> list[Path]:
    paths = [data_dir / name for name in TRAIN_JSONL_NAMES if (data_dir / name).is_file()]
    if not paths:
        raise EmberDatasetError(
            f"EMBER training JSONL not found under {data_dir}. "
            f"Expected one or more of: {', '.join(TRAIN_JSONL_NAMES)}."
        )
    return paths


def _locate_test_jsonl(data_dir: Path) -> Path | None:
    path = data_dir / TEST_JSONL_NAME
    return path if path.is_file() else None


def _memmap_vectorized_xy(
    x_path: Path,
    y_path: Path,
    *,
    feature_dim: int = EMBER_FEATURE_DIM,
) -> tuple[np.ndarray, np.ndarray]:
    if not x_path.is_file() or not y_path.is_file():
        raise EmberDatasetError(
            f"Vectorized EMBER files missing. Expected both {x_path.name} and {y_path.name}."
        )

    y = np.memmap(y_path, dtype=np.float32, mode="r")
    n_samples = int(y.shape[0])
    expected_x_bytes = n_samples * feature_dim * np.dtype(np.float32).itemsize
    actual_x_bytes = x_path.stat().st_size
    if actual_x_bytes != expected_x_bytes:
        # Allow alternate feature dims only when the byte size divides cleanly,
        # then fail validation later if it is not the official 2381-D schema.
        if n_samples == 0 or actual_x_bytes % (n_samples * np.dtype(np.float32).itemsize) != 0:
            raise EmberDatasetError(
                f"Invalid vectorized feature file {x_path.name}: size {actual_x_bytes} bytes "
                f"is inconsistent with {n_samples} labels and float32 features."
            )
        inferred_dim = actual_x_bytes // (n_samples * np.dtype(np.float32).itemsize)
        X = np.memmap(x_path, dtype=np.float32, mode="r", shape=(n_samples, inferred_dim))
    else:
        X = np.memmap(x_path, dtype=np.float32, mode="r", shape=(n_samples, feature_dim))
    return X, y


def _count_nonempty_jsonl_rows(paths: list[Path]) -> int:
    n = 0
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    n += 1
    return n


def _materialize_jsonl_split(
    jsonl_paths: list[Path],
    x_path: Path,
    y_path: Path,
    *,
    split_name: str,
    feature_dim: int = EMBER_FEATURE_DIM,
) -> None:
    """Stream JSONL into float32 memmaps, keeping only supervised (0/1) rows.

    Avoids building a Python list of 2381-D vectors (which would OOM on EMBER).
    """

    print(f"Vectorizing {split_name} JSONL → {x_path.name} (supervised rows only)...")
    n_raw = 0
    n_unlabeled = 0
    n_supervised = 0
    for obj in _read_jsonl_paths(jsonl_paths):
        n_raw += 1
        if "label" not in obj:
            raise EmberDatasetError("EMBER JSONL sample is missing required field 'label'.")
        try:
            label = int(obj["label"])
        except (TypeError, ValueError) as exc:
            raise EmberDatasetError(f"Invalid EMBER label value: {obj['label']!r}") from exc
        if label == LABEL_UNLABELED:
            n_unlabeled += 1
        elif label in SUPERVISED_LABELS:
            n_supervised += 1
        else:
            raise EmberDatasetError(
                f"Invalid EMBER label value {label}. Expected -1, 0, or 1."
            )
    if n_supervised == 0:
        raise EmberDatasetError(f"{split_name} JSONL contains no supervised samples.")

    tmp_x = x_path.with_suffix(x_path.suffix + ".tmp")
    tmp_y = y_path.with_suffix(y_path.suffix + ".tmp")
    X = np.memmap(tmp_x, dtype=np.float32, mode="w+", shape=(n_supervised, feature_dim))
    y = np.memmap(tmp_y, dtype=np.float32, mode="w+", shape=(n_supervised,))
    written = 0
    try:
        for obj in _read_jsonl_paths(jsonl_paths):
            label = int(obj["label"])
            if label not in SUPERVISED_LABELS:
                continue
            try:
                X[written] = vectorize_raw_features(obj)
            except ValueError as exc:
                raise EmberDatasetError(f"Failed to vectorize EMBER raw features: {exc}") from exc
            y[written] = float(label)
            written += 1
            if written % 25_000 == 0 or written == n_supervised:
                print(f"  {split_name}: {written}/{n_supervised} supervised vectors")
                X.flush()
                y.flush()
    except Exception:
        del X, y
        tmp_x.unlink(missing_ok=True)
        tmp_y.unlink(missing_ok=True)
        raise
    del X, y
    if written != n_supervised:
        tmp_x.unlink(missing_ok=True)
        tmp_y.unlink(missing_ok=True)
        raise EmberDatasetError(
            f"{split_name} supervised count changed between passes ({n_supervised} vs {written})."
        )
    tmp_x.replace(x_path)
    tmp_y.replace(y_path)
    print(
        f"  {split_name} done: raw={n_raw}, supervised={n_supervised}, unlabeled_skipped={n_unlabeled}"
    )


def materialize_vectorized_features(data_dir: Path) -> None:
    """Create X_*.dat / y_*.dat from official JSONL when vectorized files are absent."""

    train_ready = (data_dir / VECTORIZED_TRAIN_X).is_file() and (data_dir / VECTORIZED_TRAIN_Y).is_file()
    test_ready = (data_dir / VECTORIZED_TEST_X).is_file() and (data_dir / VECTORIZED_TEST_Y).is_file()
    if train_ready and test_ready:
        return
    if not train_ready:
        _materialize_jsonl_split(
            _locate_train_jsonl(data_dir),
            data_dir / VECTORIZED_TRAIN_X,
            data_dir / VECTORIZED_TRAIN_Y,
            split_name="train",
        )
    if not test_ready:
        test_jsonl = _locate_test_jsonl(data_dir)
        if test_jsonl is None:
            raise EmberDatasetError(
                f"EMBER test JSONL not found under {data_dir} (expected {TEST_JSONL_NAME})."
            )
        _materialize_jsonl_split(
            [test_jsonl],
            data_dir / VECTORIZED_TEST_X,
            data_dir / VECTORIZED_TEST_Y,
            split_name="test",
        )


def _vectorize_jsonl_records(
    records: Iterator[dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, int]:
    """In-memory vectorizer for small JSONL fixtures (not the 800k-row corpus)."""

    features: list[np.ndarray] = []
    labels: list[float] = []
    n_raw = 0
    for obj in records:
        n_raw += 1
        if "label" not in obj:
            raise EmberDatasetError("EMBER JSONL sample is missing required field 'label'.")
        try:
            label = float(obj["label"])
        except (TypeError, ValueError) as exc:
            raise EmberDatasetError(f"Invalid EMBER label value: {obj['label']!r}") from exc
        try:
            vector = vectorize_raw_features(obj)
        except ValueError as exc:
            raise EmberDatasetError(f"Failed to vectorize EMBER raw features: {exc}") from exc
        features.append(vector)
        labels.append(label)

    if n_raw == 0:
        raise EmberDatasetError("EMBER JSONL subset is empty.")

    X = np.vstack(features).astype(np.float32, copy=False)
    y = np.asarray(labels, dtype=np.float32)
    return X, y, n_raw


def _filter_supervised(
    X: np.ndarray,
    y: np.ndarray,
    *,
    feature_names: list[str],
    split_name: str,
) -> EmberSplit:
    if X.ndim != 2:
        raise EmberDatasetError(f"{split_name} feature matrix must be 2-D.")
    if y.ndim != 1:
        raise EmberDatasetError(f"{split_name} label vector must be 1-D.")
    if X.shape[0] != y.shape[0]:
        raise EmberDatasetError(
            f"{split_name} features and labels have mismatched row counts: "
            f"X={X.shape[0]}, y={y.shape[0]}."
        )
    if X.shape[0] == 0:
        raise EmberDatasetError(f"{split_name} feature matrix is empty.")
    if y.shape[0] == 0:
        raise EmberDatasetError(f"{split_name} label vector is empty.")

    n_raw = int(y.shape[0])
    unlabeled_mask = y == LABEL_UNLABELED
    n_unlabeled = int(np.count_nonzero(unlabeled_mask))
    supervised_mask = np.isin(y, list(SUPERVISED_LABELS))
    if not np.any(supervised_mask):
        raise EmberDatasetError(
            f"{split_name} contains no supervised labels (0=benign, 1=malicious). "
            f"Found {n_unlabeled} unlabeled (-1) samples out of {n_raw}."
        )

    # Reject unexpected label values rather than silently coercing them.
    unexpected = ~unlabeled_mask & ~supervised_mask
    if np.any(unexpected):
        bad_values = sorted({float(v) for v in y[unexpected]})
        raise EmberDatasetError(
            f"{split_name} contains invalid label values {bad_values}. "
            "Expected only -1 (unlabeled), 0 (benign), or 1 (malicious)."
        )

    if n_unlabeled == 0 and not np.any(unexpected):
        X_sup = X
        y_sup = np.asarray(y, dtype=np.int32)
    else:
        X_sup = np.asarray(X[supervised_mask], dtype=np.float32)
        y_sup = np.asarray(y[supervised_mask], dtype=np.int32)

    _validate_numeric_matrix(X_sup, split_name=split_name)
    if X_sup.shape[1] != len(feature_names):
        raise EmberDatasetError(
            f"{split_name} has {X_sup.shape[1]} features but feature name list has "
            f"{len(feature_names)} entries."
        )

    n_benign = int(np.count_nonzero(y_sup == LABEL_BENIGN))
    n_malicious = int(np.count_nonzero(y_sup == LABEL_MALICIOUS))
    if n_benign == 0 or n_malicious == 0:
        raise EmberDatasetError(
            f"{split_name} must contain both benign (0) and malicious (1) samples. "
            f"Found benign={n_benign}, malicious={n_malicious}."
        )

    return EmberSplit(
        X=X_sup,
        y=y_sup,
        feature_names=list(feature_names),
        n_raw_samples=n_raw,
        n_unlabeled_removed=n_unlabeled,
        n_benign=n_benign,
        n_malicious=n_malicious,
    )


def _validate_numeric_matrix(X: np.ndarray, *, split_name: str) -> None:
    if X.size == 0:
        raise EmberDatasetError(f"{split_name} feature matrix is empty.")
    if not np.issubdtype(X.dtype, np.floating) and not np.issubdtype(X.dtype, np.integer):
        raise EmberDatasetError(
            f"{split_name} features must be numeric; found dtype={X.dtype}."
        )
    if X.dtype == object:
        raise EmberDatasetError(
            f"{split_name} still contains object/string feature columns."
        )
    chunk = 8192
    n_nan = 0
    n_inf = 0
    for start in range(0, X.shape[0], chunk):
        block = np.asarray(X[start : start + chunk])
        n_nan += int(np.isnan(block).sum())
        n_inf += int(np.isinf(block).sum())
        if n_nan or n_inf:
            raise EmberDatasetError(
                f"{split_name} contains non-finite feature values "
                f"(nan={n_nan}, inf={n_inf}). Refusing to silently repair."
            )


def _feature_names_for_dim(n_features: int) -> list[str]:
    if n_features == EMBER_FEATURE_DIM:
        return list(EMBER_FEATURE_NAMES)
    # Structural fixtures may use a smaller width; keep deterministic names.
    return [f"feature_{i}" for i in range(n_features)]


def validate_train_test_consistency(train: EmberSplit, test: EmberSplit) -> None:
    """Ensure train/test share feature dimensionality and ordering."""

    if train.n_features != test.n_features:
        raise EmberDatasetError(
            "Train/test feature dimensions do not match: "
            f"train={train.n_features}, test={test.n_features}."
        )
    if train.feature_names != test.feature_names:
        raise EmberDatasetError(
            "Train/test feature ordering differs. "
            "Both splits must preserve identical EMBER feature order."
        )


def load_ember_training_data(
    data_dir: Path | str | None = None,
    *,
    require_official_dim: bool = True,
) -> EmberSplit:
    """Load supervised EMBER training features ``X`` and labels ``y``.

    Returns:
        EmberSplit with float32 ``X``, int32 ``y`` in {0, 1}, and feature names.
    """

    path = ensure_ember_dataset_present(data_dir)
    fmt = detect_ember_format(path)
    if fmt == "jsonl" and require_official_dim:
        materialize_vectorized_features(path)
        fmt = detect_ember_format(path)

    if fmt == "vectorized":
        X, y = _memmap_vectorized_xy(path / VECTORIZED_TRAIN_X, path / VECTORIZED_TRAIN_Y)
    else:
        X, y, _ = _vectorize_jsonl_records(_read_jsonl_paths(_locate_train_jsonl(path)))

    if require_official_dim and X.shape[1] != EMBER_FEATURE_DIM:
        raise EmberDatasetError(
            f"Training features have dimension {X.shape[1]}, expected {EMBER_FEATURE_DIM} "
            "for official EMBER 2018 feature_version=2."
        )

    feature_names = _feature_names_for_dim(int(X.shape[1]))
    return _filter_supervised(X, y, feature_names=feature_names, split_name="train")


def load_ember_test_data(
    data_dir: Path | str | None = None,
    *,
    require_official_dim: bool = True,
    required: bool = True,
) -> EmberSplit | None:
    """Load supervised EMBER test features ``X`` and labels ``y``.

    Returns:
        EmberSplit, or ``None`` when the test split is absent and ``required`` is False.
    """

    path = ensure_ember_dataset_present(data_dir)
    fmt = detect_ember_format(path)
    if fmt == "jsonl" and require_official_dim:
        materialize_vectorized_features(path)
        fmt = detect_ember_format(path)

    if fmt == "vectorized":
        x_path = path / VECTORIZED_TEST_X
        y_path = path / VECTORIZED_TEST_Y
        if not x_path.is_file() or not y_path.is_file():
            if required:
                raise EmberDatasetError(
                    f"EMBER test vectorized files not found under {path} "
                    f"(expected {VECTORIZED_TEST_X} and {VECTORIZED_TEST_Y})."
                )
            return None
        X, y = _memmap_vectorized_xy(x_path, y_path)
    else:
        test_path = _locate_test_jsonl(path)
        if test_path is None:
            if required:
                raise EmberDatasetError(
                    f"EMBER test JSONL not found under {path} (expected {TEST_JSONL_NAME})."
                )
            return None
        X, y, _ = _vectorize_jsonl_records(_read_jsonl_paths([test_path]))

    if require_official_dim and X.shape[1] != EMBER_FEATURE_DIM:
        raise EmberDatasetError(
            f"Test features have dimension {X.shape[1]}, expected {EMBER_FEATURE_DIM} "
            "for official EMBER 2018 feature_version=2."
        )

    feature_names = _feature_names_for_dim(int(X.shape[1]))
    return _filter_supervised(X, y, feature_names=feature_names, split_name="test")


def load_ember_dataset(
    data_dir: Path | str | None = None,
    *,
    require_test: bool = True,
    require_official_dim: bool = True,
) -> EmberDataset:
    """Load and validate the EMBER train/test splits.

    Training-related transforms are not fit here. The official test split is
    left intact aside from removing unlabeled rows and casting to numeric arrays.

    Returns:
        EmberDataset with matching train/test feature dimensions and ordering.
    """

    path = ensure_ember_dataset_present(data_dir)
    fmt = detect_ember_format(path)
    if fmt == "jsonl" and require_official_dim:
        materialize_vectorized_features(path)
        fmt = detect_ember_format(path)

    # Important: do not concatenate train and test before evaluation.
    train = load_ember_training_data(path, require_official_dim=require_official_dim)
    test = load_ember_test_data(
        path,
        require_official_dim=require_official_dim,
        required=require_test,
    )
    if test is not None:
        validate_train_test_consistency(train, test)

    return EmberDataset(
        train=train,
        test=test,
        data_dir=path,
        format=fmt,
        feature_names=list(train.feature_names),
    )


def _count_labels_from_jsonl(paths: list[Path]) -> tuple[int, int, int, int]:
    n_total = n_benign = n_malicious = n_unlabeled = 0
    for obj in _read_jsonl_paths(paths):
        if "label" not in obj:
            raise EmberDatasetError("EMBER JSONL sample is missing required field 'label'.")
        label = int(obj["label"])
        n_total += 1
        if label == LABEL_BENIGN:
            n_benign += 1
        elif label == LABEL_MALICIOUS:
            n_malicious += 1
        elif label == LABEL_UNLABELED:
            n_unlabeled += 1
        else:
            raise EmberDatasetError(f"Invalid EMBER label value during inspection: {label}.")
    return n_total, n_benign, n_malicious, n_unlabeled


def inspect_ember_dataset(data_dir: Path | str | None = None) -> EmberDatasetInfo:
    """Collect dataset statistics without printing the full matrices."""

    notes: list[str] = []
    try:
        path = ensure_ember_dataset_present(data_dir)
    except EmberDatasetError:
        return EmberDatasetInfo(
            data_dir=resolve_ember_data_dir(data_dir),
            format=None,
            dataset_present=False,
            n_train_samples=0,
            n_test_samples=0,
            n_features=0,
            n_train_benign=0,
            n_train_malicious=0,
            n_test_benign=0,
            n_test_malicious=0,
            n_train_unlabeled=0,
            n_test_unlabeled=0,
            feature_names=[],
            missing_value_counts={},
            notes=[MISSING_DATASET_MESSAGE],
        )

    try:
        fmt = detect_ember_format(path)
    except EmberDatasetError as exc:
        return EmberDatasetInfo(
            data_dir=path,
            format=None,
            dataset_present=True,
            n_train_samples=0,
            n_test_samples=0,
            n_features=0,
            n_train_benign=0,
            n_train_malicious=0,
            n_test_benign=0,
            n_test_malicious=0,
            n_train_unlabeled=0,
            n_test_unlabeled=0,
            feature_names=[],
            missing_value_counts={},
            notes=[str(exc)],
        )

    if fmt == "vectorized":
        dataset = load_ember_dataset(path, require_test=False, require_official_dim=False)
        train = dataset.train
        test = dataset.test
        missing = {
            "train_nan": int(np.isnan(train.X).sum()),
            "train_inf": int(np.isinf(train.X).sum()),
        }
        if test is not None:
            missing["test_nan"] = int(np.isnan(test.X).sum())
            missing["test_inf"] = int(np.isinf(test.X).sum())
        if train.n_features != EMBER_FEATURE_DIM:
            notes.append(
                f"Feature dimension is {train.n_features}; official EMBER 2018 uses "
                f"{EMBER_FEATURE_DIM}."
            )
        return EmberDatasetInfo(
            data_dir=path,
            format=fmt,
            dataset_present=True,
            n_train_samples=train.n_samples,
            n_test_samples=0 if test is None else test.n_samples,
            n_features=train.n_features,
            n_train_benign=train.n_benign,
            n_train_malicious=train.n_malicious,
            n_test_benign=0 if test is None else test.n_benign,
            n_test_malicious=0 if test is None else test.n_malicious,
            n_train_unlabeled=train.n_unlabeled_removed,
            n_test_unlabeled=0 if test is None else test.n_unlabeled_removed,
            feature_names=list(train.feature_names),
            missing_value_counts=missing,
            notes=notes,
        )

    # JSONL path: count labels without necessarily vectorizing the entire corpus twice.
    train_paths = _locate_train_jsonl(path)
    n_train, n_train_benign, n_train_malicious, n_train_unlabeled = _count_labels_from_jsonl(
        train_paths
    )
    test_path = _locate_test_jsonl(path)
    if test_path is None:
        n_test = n_test_benign = n_test_malicious = n_test_unlabeled = 0
        notes.append(f"Test JSONL ({TEST_JSONL_NAME}) not found.")
    else:
        n_test, n_test_benign, n_test_malicious, n_test_unlabeled = _count_labels_from_jsonl(
            [test_path]
        )

    notes.append(
        "Raw JSONL detected. Numerical matrices use the official 2381-D "
        "feature_version=2 vectorization when loaded for training."
    )
    return EmberDatasetInfo(
        data_dir=path,
        format=fmt,
        dataset_present=True,
        n_train_samples=n_train_benign + n_train_malicious,
        n_test_samples=n_test_benign + n_test_malicious,
        n_features=EMBER_FEATURE_DIM,
        n_train_benign=n_train_benign,
        n_train_malicious=n_train_malicious,
        n_test_benign=n_test_benign,
        n_test_malicious=n_test_malicious,
        n_train_unlabeled=n_train_unlabeled,
        n_test_unlabeled=n_test_unlabeled,
        feature_names=list(EMBER_FEATURE_NAMES),
        missing_value_counts={},
        notes=notes,
    )


def format_dataset_report(info: EmberDatasetInfo) -> str:
    """Render a concise human-readable inspection report."""

    lines = [
        "EMBER 2018 dataset inspection",
        f"  data_dir: {info.data_dir}",
        f"  present: {info.dataset_present}",
        f"  format: {info.format or 'unknown'}",
        f"  train supervised samples: {info.n_train_samples}",
        f"  test supervised samples: {info.n_test_samples}",
        f"  features: {info.n_features}",
        f"  train benign: {info.n_train_benign}",
        f"  train malicious: {info.n_train_malicious}",
        f"  train unlabeled removed/ignored: {info.n_train_unlabeled}",
        f"  test benign: {info.n_test_benign}",
        f"  test malicious: {info.n_test_malicious}",
        f"  test unlabeled removed/ignored: {info.n_test_unlabeled}",
        f"  class distribution (train): "
        f"benign={info.n_train_benign}, malicious={info.n_train_malicious}",
        f"  class distribution (test): "
        f"benign={info.n_test_benign}, malicious={info.n_test_malicious}",
        f"  missing-value summary: {info.missing_value_counts or '{}'}",
    ]
    if info.feature_names:
        preview = ", ".join(info.feature_names[:8])
        suffix = " ..." if len(info.feature_names) > 8 else ""
        lines.append(f"  feature names (preview): {preview}{suffix}")
        lines.append(f"  feature name count: {len(info.feature_names)}")
    for note in info.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)
