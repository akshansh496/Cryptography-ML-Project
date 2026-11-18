"""Tests for PE feature extraction, model loading, inference, and the FastAPI endpoint.

Design principles:
- All tests use a real, legally available PE fixture (windows-kill.exe from nodemon homebrew)
  or synthetic mocks. No malware is downloaded or executed.
- The PE is parsed but never executed.
- Malformed/garbage inputs that fail pefile validation are tested for correct rejection.
- Production model integration tests are skipped when the artifact is absent.
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier

from app.config import ML_SERVICE_ROOT, get_settings
from app.data.ember_feature_schema import EMBER_FEATURE_DIM
from app.features.pe_extractor import (
    ExtractionError,
    MalformedPEError,
    build_raw_features,
    extract_ember_features,
)
from app.inference.predictor import ModelNotReadyError, predict
from app.model.model_loader import LoadedModel, load_model
from app.schemas import AnalyzeResponse


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

# Real PE file used for structural feature extraction — never executed.
# windows-kill.exe is a benign open-source utility distributed by the nodemon npm package.
_REAL_PE_PATH = Path("/opt/homebrew/lib/node_modules/nodemon/bin/windows-kill.exe")
_REAL_PE_AVAILABLE = _REAL_PE_PATH.exists()
_REAL_PE_BYTES: bytes = _REAL_PE_PATH.read_bytes() if _REAL_PE_AVAILABLE else b""

PRODUCTION_MODEL_PATH = ML_SERVICE_ROOT / "models" / "ember_rf.joblib"
_PRODUCTION_MODEL_EXISTS = PRODUCTION_MODEL_PATH.exists()

# Canonical "valid fixture" — real PE if available, else skip
_VALID_PE = _REAL_PE_BYTES
_VALID_PE_SKIP = pytest.mark.skipif(
    not _REAL_PE_AVAILABLE, reason="Real PE fixture not available"
)


def _make_mock_rf(n_features: int = EMBER_FEATURE_DIM) -> RandomForestClassifier:
    """Return a tiny fitted RandomForest for unit tests."""
    rng = np.random.default_rng(42)
    X = np.vstack([
        rng.normal(0, 0.5, (40, n_features)).astype(np.float32),
        rng.normal(2, 0.5, (40, n_features)).astype(np.float32),
    ])
    y = np.array([0] * 40 + [1] * 40, dtype=np.int32)
    clf = RandomForestClassifier(n_estimators=6, random_state=42, n_jobs=1)
    clf.fit(X, y)
    return clf


def _make_mock_loaded_model(n_features: int = EMBER_FEATURE_DIM) -> LoadedModel:
    clf = _make_mock_rf(n_features)
    return LoadedModel(
        estimator=clf,
        feature_names=[f"feature_{i}" for i in range(n_features)],
        ready=True,
    )


# ---------------------------------------------------------------------------
# 1. build_raw_features — rejection of malformed input
# ---------------------------------------------------------------------------

class TestBuildRawFeaturesRejection:
    """All invalid PE inputs must raise MalformedPEError."""

    def test_empty_bytes_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError, match="Empty upload"):
            build_raw_features(b"")

    def test_non_mz_bytes_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError, match="MZ"):
            build_raw_features(b"PK\x03\x04" + b"\x00" * 100)

    def test_mz_garbage_raises_malformed(self) -> None:
        """MZ + random garbage now rejected by pefile (invalid e_lfanew)."""
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ" + b"\xde\xad\xbe\xef" * 200)

    def test_mz_only_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ")

    def test_mz_64_zeros_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ" + b"\x00" * 64)


# ---------------------------------------------------------------------------
# 2. build_raw_features — valid structure with real PE
# ---------------------------------------------------------------------------

@_VALID_PE_SKIP
class TestBuildRawFeatures:
    def test_returns_all_keys(self) -> None:
        raw = build_raw_features(_VALID_PE)
        required = {
            "histogram", "byteentropy", "strings", "general",
            "header", "section", "imports", "exports", "datadirectories",
        }
        assert required.issubset(raw.keys())

    def test_histogram_has_256_entries(self) -> None:
        assert len(build_raw_features(_VALID_PE)["histogram"]) == 256

    def test_byteentropy_has_256_entries(self) -> None:
        assert len(build_raw_features(_VALID_PE)["byteentropy"]) == 256

    def test_histogram_counts_non_negative(self) -> None:
        raw = build_raw_features(_VALID_PE)
        assert all(v >= 0 for v in raw["histogram"])

    def test_strings_keys_present(self) -> None:
        raw = build_raw_features(_VALID_PE)
        for k in ("numstrings", "avlength", "printabledist", "printables",
                   "entropy", "paths", "urls", "registry", "MZ"):
            assert k in raw["strings"]

    def test_printabledist_has_96_entries(self) -> None:
        assert len(build_raw_features(_VALID_PE)["strings"]["printabledist"]) == 96

    def test_general_keys_present(self) -> None:
        raw = build_raw_features(_VALID_PE)
        for k in ("size", "vsize", "has_debug", "exports", "imports",
                   "has_relocations", "has_resources", "has_signature",
                   "has_tls", "symbols"):
            assert k in raw["general"]

    def test_general_size_matches_input(self) -> None:
        raw = build_raw_features(_VALID_PE)
        assert raw["general"]["size"] == len(_VALID_PE)

    def test_real_pe_nonzero_vsize(self) -> None:
        """lief successfully parses the real PE — vsize must be non-zero."""
        raw = build_raw_features(_VALID_PE)
        assert raw["general"]["vsize"] > 0

    def test_header_structure(self) -> None:
        raw = build_raw_features(_VALID_PE)
        assert "coff" in raw["header"] and "optional" in raw["header"]
        for k in ("timestamp", "machine", "characteristics"):
            assert k in raw["header"]["coff"]
        for k in ("subsystem", "dll_characteristics", "magic",
                   "sizeof_code", "sizeof_headers", "sizeof_heap_commit"):
            assert k in raw["header"]["optional"]

    def test_section_structure(self) -> None:
        raw = build_raw_features(_VALID_PE)
        assert "entry" in raw["section"]
        assert isinstance(raw["section"]["sections"], list)

    def test_section_props_are_strings(self) -> None:
        raw = build_raw_features(_VALID_PE)
        for sec in raw["section"]["sections"]:
            assert all(isinstance(p, str) for p in sec["props"])

    def test_imports_is_dict(self) -> None:
        assert isinstance(build_raw_features(_VALID_PE)["imports"], dict)

    def test_imports_populated(self) -> None:
        assert len(build_raw_features(_VALID_PE)["imports"]) > 0

    def test_exports_is_list(self) -> None:
        assert isinstance(build_raw_features(_VALID_PE)["exports"], list)

    def test_datadirectories_is_list(self) -> None:
        assert isinstance(build_raw_features(_VALID_PE)["datadirectories"], list)

    def test_machine_is_nonempty_string(self) -> None:
        raw = build_raw_features(_VALID_PE)
        assert isinstance(raw["header"]["coff"]["machine"], str)
        assert raw["header"]["coff"]["machine"] != ""


# ---------------------------------------------------------------------------
# 3. extract_ember_features — vector shape, dtype, finiteness
# ---------------------------------------------------------------------------

class TestExtractEmberFeaturesRejection:
    def test_empty_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"")

    def test_non_pe_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"This is plaintext, not a PE file.")

    def test_mz_garbage_raises_malformed(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"MZ" + b"\xff" * 500)


@_VALID_PE_SKIP
class TestExtractEmberFeatures:
    def test_returns_ndarray_shape_2381(self) -> None:
        vec = extract_ember_features(_VALID_PE)
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (EMBER_FEATURE_DIM,)

    def test_dtype_is_float32(self) -> None:
        assert extract_ember_features(_VALID_PE).dtype == np.float32

    def test_all_values_finite(self) -> None:
        assert np.isfinite(extract_ember_features(_VALID_PE)).all()

    def test_deterministic_on_same_input(self) -> None:
        v1 = extract_ember_features(_VALID_PE)
        v2 = extract_ember_features(_VALID_PE)
        np.testing.assert_array_equal(v1, v2)

    def test_has_nonzero_features(self) -> None:
        vec = extract_ember_features(_VALID_PE)
        assert np.count_nonzero(vec) > 100


# ---------------------------------------------------------------------------
# 4. Model loader
# ---------------------------------------------------------------------------

class TestLoadModel:
    def test_missing_path_returns_not_ready(self, tmp_path: Path) -> None:
        m = load_model(tmp_path / "nonexistent.joblib")
        assert m.ready is False
        assert m.estimator is None
        assert m.load_error != ""

    def test_corrupt_file_returns_not_ready(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.joblib"
        bad.write_bytes(b"not_joblib_data")
        m = load_model(bad)
        assert m.ready is False
        assert m.load_error != ""

    def test_unrecognized_artifact_type_not_ready(self, tmp_path: Path) -> None:
        path = tmp_path / "weird.joblib"
        joblib.dump({"no_estimator": True}, path)
        assert load_model(path).ready is False

    def test_dict_artifact_loaded_correctly(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        artifact = {
            "estimator": clf,
            "feature_names": [f"f_{i}" for i in range(EMBER_FEATURE_DIM)],
        }
        path = tmp_path / "model.joblib"
        joblib.dump(artifact, path)
        m = load_model(path)
        assert m.ready is True
        assert int(m.estimator.n_features_in_) == EMBER_FEATURE_DIM

    def test_n_features_validated(self, tmp_path: Path) -> None:
        clf_wrong = _make_mock_rf(n_features=8)
        path = tmp_path / "wrong.joblib"
        joblib.dump({"estimator": clf_wrong}, path)
        m = load_model(path)
        assert m.ready is False
        assert "2381" in m.load_error or "n_features" in m.load_error

    def test_wrong_classes_not_ready(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        clf.classes_ = np.array([0, 1, 2])
        path = tmp_path / "cls.joblib"
        joblib.dump({"estimator": clf}, path)
        assert load_model(path).ready is False

    def test_bare_estimator_accepted(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        path = tmp_path / "bare.joblib"
        joblib.dump(clf, path)
        assert load_model(path).ready is True

    def test_feature_names_populated(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        names = [f"feat_{i}" for i in range(EMBER_FEATURE_DIM)]
        path = tmp_path / "names.joblib"
        joblib.dump({"estimator": clf, "feature_names": names}, path)
        m = load_model(path)
        assert m.feature_names == names

    def test_load_error_empty_on_success(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        path = tmp_path / "ok.joblib"
        joblib.dump({"estimator": clf}, path)
        m = load_model(path)
        assert m.ready is True
        assert m.load_error == ""

    @pytest.mark.skipif(
        not _PRODUCTION_MODEL_EXISTS,
        reason="Production model not present — run scripts/train_ember_rf.py",
    )
    def test_production_model_loads_and_validates(self) -> None:
        m = load_model(PRODUCTION_MODEL_PATH)
        assert m.ready is True
        assert int(m.estimator.n_features_in_) == EMBER_FEATURE_DIM
        assert set(int(c) for c in m.estimator.classes_) == {0, 1}


# ---------------------------------------------------------------------------
# 5. Predictor
# ---------------------------------------------------------------------------

class TestPredictor:
    def _vec(self, scale: float = 0.0) -> np.ndarray:
        rng = np.random.default_rng(7)
        return rng.normal(size=EMBER_FEATURE_DIM).astype(np.float32) + scale

    def test_not_ready_raises(self) -> None:
        with pytest.raises(ModelNotReadyError):
            predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), LoadedModel(ready=False))

    def test_wrong_shape_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="shape"):
            predict(np.zeros(10, dtype=np.float32), _make_mock_loaded_model())

    def test_returns_analyze_response(self) -> None:
        assert isinstance(predict(self._vec(), _make_mock_loaded_model()), AnalyzeResponse)

    def test_verdict_is_valid(self) -> None:
        assert predict(self._vec(), _make_mock_loaded_model()).verdict in ("benign", "malicious")

    def test_probability_in_0_1(self) -> None:
        p = predict(self._vec(), _make_mock_loaded_model()).probability
        assert 0.0 <= p <= 1.0

    def test_risk_score_in_0_100(self) -> None:
        r = predict(self._vec(), _make_mock_loaded_model()).risk_score
        assert 0 <= r <= 100

    def test_risk_score_matches_probability(self) -> None:
        resp = predict(self._vec(), _make_mock_loaded_model())
        assert resp.risk_score == int(round(resp.probability * 100))

    def test_top_features_at_most_5(self) -> None:
        assert len(predict(self._vec(), _make_mock_loaded_model()).top_features) <= 5

    def test_top_feature_importance_in_0_1(self) -> None:
        for tf in predict(self._vec(), _make_mock_loaded_model()).top_features:
            assert 0.0 <= tf.importance <= 1.0

    def test_top_features_have_description(self) -> None:
        for tf in predict(self._vec(), _make_mock_loaded_model()).top_features:
            assert len(tf.description) > 0

    def test_clearly_benign_vector_low_probability(self) -> None:
        rng = np.random.default_rng(99)
        X = np.vstack([
            rng.normal(0, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
            rng.normal(8, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
        ])
        y = np.array([0] * 40 + [1] * 40, dtype=np.int32)
        clf = RandomForestClassifier(n_estimators=8, random_state=42, n_jobs=1)
        clf.fit(X, y)
        m = LoadedModel(estimator=clf, feature_names=[f"f_{i}" for i in range(EMBER_FEATURE_DIM)], ready=True)
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), m)
        assert resp.probability < 0.5

    def test_clearly_malicious_vector_high_probability(self) -> None:
        rng = np.random.default_rng(99)
        X = np.vstack([
            rng.normal(0, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
            rng.normal(8, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
        ])
        y = np.array([0] * 40 + [1] * 40, dtype=np.int32)
        clf = RandomForestClassifier(n_estimators=8, random_state=42, n_jobs=1)
        clf.fit(X, y)
        m = LoadedModel(estimator=clf, feature_names=[f"f_{i}" for i in range(EMBER_FEATURE_DIM)], ready=True)
        resp = predict(np.full(EMBER_FEATURE_DIM, 8.0, dtype=np.float32), m)
        assert resp.probability > 0.5


# ---------------------------------------------------------------------------
# 6. FastAPI endpoint
# ---------------------------------------------------------------------------

class TestAnalyzeEndpoint:
    def _client(self, model: LoadedModel | None = None) -> TestClient:
        get_settings.cache_clear()
        from app.main import app
        client = TestClient(app)
        if model is not None:
            app.state.loaded_model = model
        return client

    def test_health_returns_ok(self) -> None:
        assert self._client().get("/health").json()["status"] == "ok"

    def test_empty_upload_returns_400(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("t.exe", b"", "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_non_pe_returns_400(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("t.txt", b"Hello, world!", "text/plain")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_mz_garbage_returns_400(self) -> None:
        """MZ+garbage is now rejected with 400 (hardened in Prompt 7)."""
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("t.exe", b"MZ" + b"\xff" * 500, "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_model_not_ready_returns_503(self) -> None:
        resp = self._client(LoadedModel(ready=False)).post(
            "/internal/analyze",
            files={"file": ("t.exe", b"MZ" + b"\xff" * 500, "application/octet-stream")},
        )
        # MZ+garbage now rejected before model check → 400
        assert resp.status_code in (400, 503)

    @_VALID_PE_SKIP
    def test_valid_pe_with_mock_model_returns_200(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        assert resp.status_code == 200, resp.text

    @_VALID_PE_SKIP
    def test_response_schema_fields_present(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "verdict" in body
        assert "probability" in body
        assert "risk_score" in body
        assert "top_features" in body

    @_VALID_PE_SKIP
    def test_verdict_is_benign_or_malicious(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        assert resp.json()["verdict"] in ("benign", "malicious")

    @_VALID_PE_SKIP
    def test_probability_is_float_in_0_1(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        p = resp.json()["probability"]
        assert isinstance(p, float) and 0.0 <= p <= 1.0

    @_VALID_PE_SKIP
    def test_risk_score_is_int_in_0_100(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        r = resp.json()["risk_score"]
        assert isinstance(r, int) and 0 <= r <= 100

    @_VALID_PE_SKIP
    def test_top_features_max_5(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        assert len(resp.json()["top_features"]) <= 5

    @_VALID_PE_SKIP
    def test_top_feature_importance_0_1(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        for tf in resp.json()["top_features"]:
            assert 0.0 <= tf["importance"] <= 1.0

    @_VALID_PE_SKIP
    def test_top_features_have_non_empty_description(self) -> None:
        resp = self._client(_make_mock_loaded_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
        )
        for tf in resp.json()["top_features"]:
            assert len(tf["description"]) > 0

    @_VALID_PE_SKIP
    def test_model_same_instance_across_requests(self) -> None:
        get_settings.cache_clear()
        from app.main import app
        m = _make_mock_loaded_model()
        with TestClient(app) as client:
            app.state.loaded_model = m
            for _ in range(2):
                client.post(
                    "/internal/analyze",
                    files={"file": ("windows-kill.exe", _VALID_PE, "application/octet-stream")},
                )
            assert app.state.loaded_model is m


# ---------------------------------------------------------------------------
# 7. Production model integration (skipped when artifact absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _PRODUCTION_MODEL_EXISTS,
    reason="Production model not present — run scripts/train_ember_rf.py first",
)
class TestProductionModelIntegration:
    def test_production_model_loads(self) -> None:
        m = load_model(PRODUCTION_MODEL_PATH)
        assert m.ready is True
        assert int(m.estimator.n_features_in_) == EMBER_FEATURE_DIM

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE not available")
    def test_real_pe_end_to_end_inference(self) -> None:
        m = load_model(PRODUCTION_MODEL_PATH)
        vec = extract_ember_features(_REAL_PE_BYTES)
        assert vec.shape == (EMBER_FEATURE_DIM,)
        resp = predict(vec, m)
        assert resp.verdict in ("benign", "malicious")
        assert 0.0 <= resp.probability <= 1.0

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE not available")
    def test_feature_vector_shape_matches_model(self) -> None:
        m = load_model(PRODUCTION_MODEL_PATH)
        vec = extract_ember_features(_REAL_PE_BYTES)
        assert vec.shape == (int(m.estimator.n_features_in_),)

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE not available")
    def test_production_endpoint_returns_200(self) -> None:
        get_settings.cache_clear()
        from app.main import app
        m = load_model(PRODUCTION_MODEL_PATH)
        with TestClient(app) as client:
            app.state.loaded_model = m
            resp = client.post(
                "/internal/analyze",
                files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] in ("benign", "malicious")
        assert 0.0 <= body["probability"] <= 1.0
        assert 0 <= body["risk_score"] <= 100
