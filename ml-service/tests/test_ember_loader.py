"""Unit tests for EMBER 2018 loading and preprocessing.

These tests use tiny structural fixtures that mirror the official on-disk layout.
They do not download EMBER, do not fabricate a production model, and do not
substitute unrelated malware corpora.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from app.data import (
    EMBER_FEATURE_DIM,
    EmberDatasetError,
    detect_ember_format,
    inspect_ember_dataset,
    load_ember_dataset,
    load_ember_test_data,
    load_ember_training_data,
)
from app.data.ember_loader import MISSING_DATASET_MESSAGE
from app.data.ember_vectorizer import vectorize_raw_features


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


def _minimal_raw_sample(label: int, *, seed: int = 0) -> dict:
    """Build a minimal but schema-valid EMBER raw JSON object."""

    rng = np.random.default_rng(seed)
    histogram = rng.integers(0, 10, size=256).tolist()
    byteentropy = rng.integers(0, 10, size=256).tolist()
    return {
        "sha256": f"{seed:064x}",
        "appeared": "2018-01",
        "label": label,
        "avclass": "",
        "histogram": histogram,
        "byteentropy": byteentropy,
        "strings": {
            "numstrings": 3,
            "avlength": 5.0,
            "printabledist": [0] * 96,
            "printables": 0,
            "entropy": 0.0,
            "paths": 0,
            "urls": 0,
            "registry": 0,
            "MZ": 1,
        },
        "general": {
            "size": 1000 + seed,
            "vsize": 2000,
            "has_debug": 0,
            "exports": 0,
            "imports": 2,
            "has_relocations": 1,
            "has_resources": 0,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        },
        "header": {
            "coff": {
                "timestamp": 1,
                "machine": "I386",
                "characteristics": ["EXECUTABLE_IMAGE"],
            },
            "optional": {
                "subsystem": "WINDOWS_GUI",
                "dll_characteristics": ["DYNAMIC_BASE"],
                "magic": "PE32",
                "major_image_version": 0,
                "minor_image_version": 0,
                "major_linker_version": 1,
                "minor_linker_version": 0,
                "major_operating_system_version": 4,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 4,
                "minor_subsystem_version": 0,
                "sizeof_code": 512,
                "sizeof_headers": 1024,
                "sizeof_heap_commit": 4096,
            },
        },
        "section": {
            "entry": ".text",
            "sections": [
                {
                    "name": ".text",
                    "size": 100,
                    "entropy": 5.5,
                    "vsize": 128,
                    "props": ["MEM_READ", "MEM_EXECUTE"],
                }
            ],
        },
        "imports": {"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
        "exports": [],
        "datadirectories": [
            {"name": "EXPORT_TABLE", "size": 0, "virtual_address": 0},
            {"name": "IMPORT_TABLE", "size": 10, "virtual_address": 20},
        ],
    }


def _write_jsonl(path: Path, samples: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample) + "\n")


def test_missing_dataset_path_produces_clear_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(EmberDatasetError, match="EMBER 2018 dataset not found") as exc_info:
        load_ember_dataset(missing)
    assert str(exc_info.value) == MISSING_DATASET_MESSAGE


def test_no_synthetic_data_when_dataset_unavailable(tmp_path: Path) -> None:
    missing = tmp_path / "empty-ember"
    info = inspect_ember_dataset(missing)
    assert info.dataset_present is False
    assert info.n_train_samples == 0
    assert info.n_test_samples == 0
    assert any("not found" in note.lower() for note in info.notes)
    with pytest.raises(EmberDatasetError):
        load_ember_training_data(missing)


def test_invalid_dataset_produces_clear_error(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    # Empty directory: present but missing expected files.
    with pytest.raises(EmberDatasetError, match="dataset files not found"):
        detect_ember_format(data_dir)

    # Malformed JSONL.
    _write_jsonl(data_dir / "train_features_0.jsonl", [])
    (data_dir / "train_features_0.jsonl").write_text("{not-json\n", encoding="utf-8")
    with pytest.raises(EmberDatasetError, match="Malformed JSONL"):
        load_ember_training_data(data_dir, require_official_dim=True)


def test_vectorized_train_test_shapes_and_classes(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    n_features = 8
    X_train = np.array(
        [
            [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
            [0.2, 0.1, 0.4, 0.3, 0.6, 0.5, 0.8, 0.7],
            [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2],
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        ],
        dtype=np.float32,
    )
    y_train = np.array([0, 1, -1, 1], dtype=np.float32)
    X_test = np.array(
        [
            [0.3, 0.3, 0.3, 0.3, 0.3, 0.3, 0.3, 0.3],
            [0.4, 0.4, 0.4, 0.4, 0.4, 0.4, 0.4, 0.4],
        ],
        dtype=np.float32,
    )
    y_test = np.array([0, 1], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(data_dir, x_name="X_test.dat", y_name="y_test.dat", X=X_test, y=y_test)

    dataset = load_ember_dataset(data_dir, require_test=True, require_official_dim=False)

    assert dataset.train.X.shape[0] == dataset.train.y.shape[0] == 3
    assert dataset.test is not None
    assert dataset.test.X.shape[0] == dataset.test.y.shape[0] == 2
    assert dataset.train.X.shape[1] == dataset.test.X.shape[1] == n_features
    assert set(dataset.train.y.tolist()) == {0, 1}
    assert set(dataset.test.y.tolist()) == {0, 1}
    assert dataset.train.n_unlabeled_removed == 1
    assert dataset.train.n_benign == 1
    assert dataset.train.n_malicious == 2


def test_feature_ordering_is_deterministic(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    X_train = np.arange(12, dtype=np.float32).reshape(3, 4)
    y_train = np.array([0, 1, 0], dtype=np.float32)
    X_test = np.arange(8, dtype=np.float32).reshape(2, 4)
    y_test = np.array([1, 0], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(data_dir, x_name="X_test.dat", y_name="y_test.dat", X=X_test, y=y_test)

    first = load_ember_dataset(data_dir, require_official_dim=False)
    second = load_ember_dataset(data_dir, require_official_dim=False)
    assert first.feature_names == second.feature_names
    assert first.train.feature_names == first.test.feature_names
    assert first.feature_names == [f"feature_{i}" for i in range(4)]


def test_mismatched_feature_dimensions_fail(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    X_train = np.ones((4, 6), dtype=np.float32)
    y_train = np.array([0, 1, 0, 1], dtype=np.float32)
    X_test = np.ones((2, 5), dtype=np.float32)
    y_test = np.array([0, 1], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(data_dir, x_name="X_test.dat", y_name="y_test.dat", X=X_test, y=y_test)

    with pytest.raises(EmberDatasetError, match="feature dimensions do not match"):
        load_ember_dataset(data_dir, require_official_dim=False)


def test_row_count_mismatch_fails(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    # 10 bytes cannot form an integral float32 feature matrix for 2 labels.
    (data_dir / "X_train.dat").write_bytes(b"\x00" * 10)
    np.array([0, 1], dtype=np.float32).tofile(data_dir / "y_train.dat")
    _write_vectorized_split(
        data_dir,
        x_name="X_test.dat",
        y_name="y_test.dat",
        X=np.ones((2, 4), dtype=np.float32),
        y=np.array([0, 1], dtype=np.float32),
    )

    with pytest.raises(EmberDatasetError, match="inconsistent"):
        load_ember_training_data(data_dir, require_official_dim=False)


def test_both_classes_required(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    X_train = np.ones((3, 4), dtype=np.float32)
    y_train = np.array([0, 0, -1], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(
        data_dir,
        x_name="X_test.dat",
        y_name="y_test.dat",
        X=np.ones((2, 4), dtype=np.float32),
        y=np.array([0, 1], dtype=np.float32),
    )
    with pytest.raises(EmberDatasetError, match="both benign"):
        load_ember_training_data(data_dir, require_official_dim=False)


def test_jsonl_vectorizes_to_official_dimension(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    train_samples = [
        _minimal_raw_sample(0, seed=1),
        _minimal_raw_sample(1, seed=2),
        _minimal_raw_sample(-1, seed=3),
    ]
    test_samples = [
        _minimal_raw_sample(0, seed=4),
        _minimal_raw_sample(1, seed=5),
    ]
    _write_jsonl(data_dir / "train_features_0.jsonl", train_samples)
    _write_jsonl(data_dir / "test_features.jsonl", test_samples)

    dataset = load_ember_dataset(data_dir, require_test=True, require_official_dim=True)
    assert dataset.format in {"jsonl", "vectorized"}
    assert dataset.train.X.shape == (2, EMBER_FEATURE_DIM)
    assert dataset.test is not None
    assert dataset.test.X.shape == (2, EMBER_FEATURE_DIM)
    assert dataset.train.feature_names == dataset.test.feature_names
    assert len(dataset.feature_names) == EMBER_FEATURE_DIM
    assert set(dataset.train.y.tolist()) == {0, 1}

    vector = vectorize_raw_features(_minimal_raw_sample(0, seed=99))
    assert vector.shape == (EMBER_FEATURE_DIM,)
    assert vector.dtype == np.float32


def test_non_finite_features_are_rejected(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    X_train = np.ones((2, 4), dtype=np.float32)
    X_train[0, 0] = np.nan
    y_train = np.array([0, 1], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(
        data_dir,
        x_name="X_test.dat",
        y_name="y_test.dat",
        X=np.ones((2, 4), dtype=np.float32),
        y=np.array([0, 1], dtype=np.float32),
    )
    with pytest.raises(EmberDatasetError, match="non-finite"):
        load_ember_training_data(data_dir, require_official_dim=False)


def test_load_helpers_match_dataset_bundle(tmp_path: Path) -> None:
    data_dir = tmp_path / "ember2018"
    data_dir.mkdir()
    X_train = np.arange(16, dtype=np.float32).reshape(4, 4)
    y_train = np.array([0, 1, 0, 1], dtype=np.float32)
    X_test = np.arange(8, dtype=np.float32).reshape(2, 4) + 10
    y_test = np.array([1, 0], dtype=np.float32)
    _write_vectorized_split(data_dir, x_name="X_train.dat", y_name="y_train.dat", X=X_train, y=y_train)
    _write_vectorized_split(data_dir, x_name="X_test.dat", y_name="y_test.dat", X=X_test, y=y_test)

    train = load_ember_training_data(data_dir, require_official_dim=False)
    test = load_ember_test_data(data_dir, require_official_dim=False)
    bundled = load_ember_dataset(data_dir, require_official_dim=False)

    assert test is not None
    assert train.X.shape == bundled.train.X.shape
    assert test.X.shape == bundled.test.X.shape
    np.testing.assert_array_equal(train.y, bundled.train.y)
    np.testing.assert_array_equal(test.y, bundled.test.y)
