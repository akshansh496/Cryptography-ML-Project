"""Prompt 7 regression tests: EMBER parity, hardened PE validation, and inference.

Test categories:
  1. Vectorizer parity (vs. official EMBER process_raw_features) — uses real EMBER JSONL records.
  2. Feature ordering and dimension invariants.
  3. Malformed-file rejection.
  4. Valid PE extraction from a real, legally available PE fixture.
  5. Model loading and inference behaviour.
  6. Response schema contracts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

from app.config import ML_SERVICE_ROOT, get_settings
from app.data.ember_feature_schema import (
    EMBER_FEATURE_DIM,
    EMBER_FEATURE_GROUPS,
    EMBER_FEATURE_NAMES,
)
from app.data.ember_vectorizer import vectorize_raw_features
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
# Paths and availability flags
# ---------------------------------------------------------------------------

_DATA_DIR = ML_SERVICE_ROOT / "data" / "ember2018"
_JSONL_AVAILABLE = (_DATA_DIR / "test_features.jsonl").exists()

_REAL_PE_PATH = Path("/opt/homebrew/lib/node_modules/nodemon/bin/windows-kill.exe")
_REAL_PE_AVAILABLE = _REAL_PE_PATH.exists()
_REAL_PE_BYTES: bytes = _REAL_PE_PATH.read_bytes() if _REAL_PE_AVAILABLE else b""

_PRODUCTION_MODEL_PATH = ML_SERVICE_ROOT / "models" / "ember_rf.joblib"
_PRODUCTION_MODEL_EXISTS = _PRODUCTION_MODEL_PATH.exists()


# ---------------------------------------------------------------------------
# Reference implementation of official EMBER process_raw_features
# (direct port of elastic/ember features.py for parity comparison)
# ---------------------------------------------------------------------------

def _ref_histogram(r: list[Any]) -> np.ndarray:
    c = np.array(r, dtype=np.float32)
    s = c.sum()
    return c / s if s > 0 else c


def _ref_byteentropy(r: list[Any]) -> np.ndarray:
    c = np.array(r, dtype=np.float32)
    s = c.sum()
    return c / s if s > 0 else c


def _ref_strings(r: dict[str, Any]) -> np.ndarray:
    h = np.asarray(r["printabledist"], dtype=np.float32)
    d = float(r["printables"]) if r["printables"] > 0 else 1.0
    return np.hstack([
        r["numstrings"], r["avlength"], r["printables"], h / d,
        r["entropy"], r["paths"], r["urls"], r["registry"], r["MZ"],
    ]).astype(np.float32)


def _ref_general(r: dict[str, Any]) -> np.ndarray:
    return np.asarray([
        r["size"], r["vsize"], r["has_debug"], r["exports"], r["imports"],
        r["has_relocations"], r["has_resources"], r["has_signature"],
        r["has_tls"], r["symbols"],
    ], dtype=np.float32)


def _ref_header(r: dict[str, Any]) -> np.ndarray:
    c, o = r["coff"], r["optional"]
    return np.hstack([
        c["timestamp"],
        FeatureHasher(10, input_type="string").transform([[c["machine"]]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([c["characteristics"]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([[o["subsystem"]]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([o["dll_characteristics"]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([[o["magic"]]]).toarray()[0],
        o["major_image_version"], o["minor_image_version"],
        o["major_linker_version"], o["minor_linker_version"],
        o["major_operating_system_version"], o["minor_operating_system_version"],
        o["major_subsystem_version"], o["minor_subsystem_version"],
        o["sizeof_code"], o["sizeof_headers"], o["sizeof_heap_commit"],
    ]).astype(np.float32)


def _ref_section(r: dict[str, Any]) -> np.ndarray:
    secs = r["sections"]
    entry = r.get("entry", "")
    gen = [
        len(secs),
        sum(1 for s in secs if s["size"] == 0),
        sum(1 for s in secs if s["name"] == ""),
        sum(1 for s in secs if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
        sum(1 for s in secs if "MEM_WRITE" in s["props"]),
    ]
    # Entry name hashed by iterating characters (official EMBER behaviour, lief 0.9 + old sklearn)
    # Modern sklearn equivalent: list(entry) — same as our vectorizer
    return np.hstack([
        gen,
        FeatureHasher(50, input_type="pair").transform([[(s["name"], s["size"]) for s in secs]]).toarray()[0],
        FeatureHasher(50, input_type="pair").transform([[(s["name"], s["entropy"]) for s in secs]]).toarray()[0],
        FeatureHasher(50, input_type="pair").transform([[(s["name"], s["vsize"]) for s in secs]]).toarray()[0],
        FeatureHasher(50, input_type="string").transform([list(entry)]).toarray()[0],
        FeatureHasher(50, input_type="string").transform([[p for s in secs for p in s["props"] if s["name"] == entry]]).toarray()[0],
    ]).astype(np.float32)


def _ref_imports(r: dict[str, Any]) -> np.ndarray:
    libs = list({lib.lower() for lib in r.keys()})
    imps = [f"{lib.lower()}:{e}" for lib, elist in r.items() for e in elist]
    return np.hstack([
        FeatureHasher(256, input_type="string").transform([libs]).toarray()[0],
        FeatureHasher(1024, input_type="string").transform([imps]).toarray()[0],
    ]).astype(np.float32)


def _ref_exports(r: list[str]) -> np.ndarray:
    return FeatureHasher(128, input_type="string").transform([r]).toarray()[0].astype(np.float32)


def _ref_datadirs(r: list[dict[str, Any]]) -> np.ndarray:
    f = np.zeros(30, dtype=np.float32)
    for i in range(15):
        if i < len(r):
            f[2 * i] = r[i]["size"]
            f[2 * i + 1] = r[i]["virtual_address"]
    return f


def reference_vectorize(rec: dict[str, Any]) -> np.ndarray:
    """Official EMBER process_raw_features logic (elastic/ember features.py port)."""
    return np.hstack([
        _ref_histogram(rec["histogram"]),
        _ref_byteentropy(rec["byteentropy"]),
        _ref_strings(rec["strings"]),
        _ref_general(rec["general"]),
        _ref_header(rec["header"]),
        _ref_section(rec["section"]),
        _ref_imports(rec["imports"]),
        _ref_exports(rec["exports"]),
        _ref_datadirs(rec["datadirectories"]),
    ]).astype(np.float32)


def _load_jsonl_records(n: int = 20, label: int | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(_DATA_DIR / "test_features.jsonl") as f:
        for line in f:
            if len(records) >= n:
                break
            rec = json.loads(line)
            if rec.get("label") not in (0, 1):
                continue
            if label is not None and rec.get("label") != label:
                continue
            records.append(rec)
    return records


# ---------------------------------------------------------------------------
# Helpers for model mocking
# ---------------------------------------------------------------------------

def _make_mock_rf(n_features: int = EMBER_FEATURE_DIM) -> RandomForestClassifier:
    rng = np.random.default_rng(42)
    X = np.vstack([
        rng.normal(0, 0.5, (40, n_features)).astype(np.float32),
        rng.normal(2, 0.5, (40, n_features)).astype(np.float32),
    ])
    y = np.array([0] * 40 + [1] * 40, dtype=np.int32)
    clf = RandomForestClassifier(n_estimators=6, random_state=42, n_jobs=1)
    clf.fit(X, y)
    return clf


def _make_mock_model(n_features: int = EMBER_FEATURE_DIM) -> LoadedModel:
    clf = _make_mock_rf(n_features)
    return LoadedModel(
        estimator=clf,
        feature_names=[f"f_{i}" for i in range(n_features)],
        ready=True,
    )


# ---------------------------------------------------------------------------
# 1. Vectorizer parity vs. official EMBER process_raw_features
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _JSONL_AVAILABLE, reason="EMBER JSONL not available")
class TestVectorizerParity:
    """All 2381 features must exactly match the reference implementation
    for every EMBER JSONL record tested. Max allowed diff: 0."""

    def _records(self, n: int = 20) -> list[dict[str, Any]]:
        return _load_jsonl_records(n)

    def test_all_groups_exact_single_benign(self) -> None:
        recs = _load_jsonl_records(1, label=0)
        assert recs, "No benign JSONL records found"
        rec = recs[0]
        ref = reference_vectorize(rec)
        ours = vectorize_raw_features(rec)
        assert np.array_equal(ref, ours), (
            f"Parity failed: max_diff={float(np.abs(ref - ours).max()):.2e}"
        )

    def test_all_groups_exact_single_malicious(self) -> None:
        recs = _load_jsonl_records(1, label=1)
        assert recs, "No malicious JSONL records found"
        rec = recs[0]
        ref = reference_vectorize(rec)
        ours = vectorize_raw_features(rec)
        assert np.array_equal(ref, ours)

    def test_parity_on_20_records(self) -> None:
        recs = self._records(20)
        assert len(recs) >= 10, "Too few JSONL records available for parity test"
        mismatches = []
        for i, rec in enumerate(recs):
            ref = reference_vectorize(rec)
            ours = vectorize_raw_features(rec)
            if not np.array_equal(ref, ours):
                mismatches.append((i, float(np.abs(ref - ours).max())))
        assert not mismatches, (
            f"Vectorizer parity failures on {len(mismatches)}/{len(recs)} records: {mismatches}"
        )

    def test_per_group_parity(self) -> None:
        """Each feature group matches exactly on a real EMBER record."""
        recs = _load_jsonl_records(1, label=0)
        rec = recs[0]

        groups_ref = [
            _ref_histogram(rec["histogram"]),
            _ref_byteentropy(rec["byteentropy"]),
            _ref_strings(rec["strings"]),
            _ref_general(rec["general"]),
            _ref_header(rec["header"]),
            _ref_section(rec["section"]),
            _ref_imports(rec["imports"]),
            _ref_exports(rec["exports"]),
            _ref_datadirs(rec["datadirectories"]),
        ]
        ref_vec = np.hstack(groups_ref).astype(np.float32)
        our_vec = vectorize_raw_features(rec)

        offset = 0
        group_failures = []
        for name, dim in EMBER_FEATURE_GROUPS:
            r = ref_vec[offset:offset + dim]
            u = our_vec[offset:offset + dim]
            if not np.array_equal(r, u):
                group_failures.append(
                    f"{name}: max_diff={float(np.abs(r-u).max()):.2e} n_differ={int(np.sum(r!=u))}"
                )
            offset += dim
        assert not group_failures, f"Group parity failures: {group_failures}"

    def test_histogram_group_exact(self) -> None:
        rec = _load_jsonl_records(1)[0]
        ref = _ref_histogram(rec["histogram"])
        ours = vectorize_raw_features(rec)[:256]
        np.testing.assert_array_equal(ref, ours)

    def test_byteentropy_group_exact(self) -> None:
        rec = _load_jsonl_records(1)[0]
        ref = _ref_byteentropy(rec["byteentropy"])
        ours = vectorize_raw_features(rec)[256:512]
        np.testing.assert_array_equal(ref, ours)

    def test_strings_group_exact(self) -> None:
        rec = _load_jsonl_records(1)[0]
        ref = _ref_strings(rec["strings"])
        ours = vectorize_raw_features(rec)[512:616]
        np.testing.assert_array_equal(ref, ours)

    def test_general_group_exact(self) -> None:
        rec = _load_jsonl_records(1)[0]
        ref = _ref_general(rec["general"])
        ours = vectorize_raw_features(rec)[616:626]
        np.testing.assert_array_equal(ref, ours)

    def test_imports_group_exact(self) -> None:
        rec = _load_jsonl_records(1)[0]
        ref = _ref_imports(rec["imports"])
        ours = vectorize_raw_features(rec)[628 + 62: 628 + 62 + 1280]
        # Find exact offset
        offset = sum(dim for _, dim in EMBER_FEATURE_GROUPS[:6])
        ours = vectorize_raw_features(rec)[offset:offset + 1280]
        np.testing.assert_array_equal(ref, ours)

    def test_datadirectory_name_does_not_affect_feature_values(self) -> None:
        """The 'name' field in datadirectories is never read by process_raw_features
        (uses positional indexing only). Changing the name must not change values."""
        from app.data.ember_vectorizer import _datadirectories as our_dd
        dd_a = [{"name": "EXPORT_TABLE", "size": 100, "virtual_address": 0x1000}]
        dd_b = [{"name": "COMPLETELY_WRONG_NAME", "size": 100, "virtual_address": 0x1000}]
        np.testing.assert_array_equal(our_dd(dd_a), our_dd(dd_b))


# ---------------------------------------------------------------------------
# 2. Feature dimension and ordering invariants
# ---------------------------------------------------------------------------

class TestFeatureSchemaInvariants:
    def test_total_dim_is_2381(self) -> None:
        assert EMBER_FEATURE_DIM == 2381

    def test_group_dims_sum_to_total(self) -> None:
        assert sum(dim for _, dim in EMBER_FEATURE_GROUPS) == EMBER_FEATURE_DIM

    def test_group_ordering(self) -> None:
        expected_order = [
            "histogram", "byteentropy", "strings", "general", "header",
            "section", "imports", "exports", "datadirectories",
        ]
        assert [name for name, _ in EMBER_FEATURE_GROUPS] == expected_order

    def test_group_dims_exact(self) -> None:
        expected = {
            "histogram": 256, "byteentropy": 256, "strings": 104,
            "general": 10, "header": 62, "section": 255,
            "imports": 1280, "exports": 128, "datadirectories": 30,
        }
        for name, dim in EMBER_FEATURE_GROUPS:
            assert dim == expected[name], f"{name}: expected {expected[name]}, got {dim}"

    def test_feature_names_length(self) -> None:
        assert len(EMBER_FEATURE_NAMES) == EMBER_FEATURE_DIM

    def test_feature_names_unique(self) -> None:
        assert len(set(EMBER_FEATURE_NAMES)) == EMBER_FEATURE_DIM

    def test_feature_names_group_prefixed(self) -> None:
        offset = 0
        for name, dim in EMBER_FEATURE_GROUPS:
            for i in range(dim):
                assert EMBER_FEATURE_NAMES[offset + i] == f"{name}_{i}"
            offset += dim

    def test_feature_names_match_group_boundaries(self) -> None:
        offset = 0
        for name, dim in EMBER_FEATURE_GROUPS:
            first = EMBER_FEATURE_NAMES[offset]
            last = EMBER_FEATURE_NAMES[offset + dim - 1]
            assert first == f"{name}_0"
            assert last == f"{name}_{dim - 1}"
            offset += dim

    @pytest.mark.skipif(not _JSONL_AVAILABLE, reason="EMBER JSONL not available")
    def test_vectorizer_output_shape_matches_schema(self) -> None:
        recs = _load_jsonl_records(1)
        vec = vectorize_raw_features(recs[0])
        assert vec.shape == (EMBER_FEATURE_DIM,)

    @pytest.mark.skipif(not _JSONL_AVAILABLE, reason="EMBER JSONL not available")
    def test_vectorizer_output_dtype_float32(self) -> None:
        recs = _load_jsonl_records(1)
        vec = vectorize_raw_features(recs[0])
        assert vec.dtype == np.float32

    @pytest.mark.skipif(not _JSONL_AVAILABLE, reason="EMBER JSONL not available")
    def test_vectorizer_output_all_finite(self) -> None:
        for rec in _load_jsonl_records(5):
            vec = vectorize_raw_features(rec)
            assert np.isfinite(vec).all(), f"Non-finite values in vectorizer output"


# ---------------------------------------------------------------------------
# 3. Hardened malformed-file rejection
# ---------------------------------------------------------------------------

class TestMalformedFileRejection:
    """All inputs that fail pefile structural validation must raise MalformedPEError."""

    def test_empty_bytes(self) -> None:
        with pytest.raises(MalformedPEError, match="Empty upload"):
            build_raw_features(b"")

    def test_non_mz_plaintext(self) -> None:
        with pytest.raises(MalformedPEError, match="MZ"):
            build_raw_features(b"This is a text file, not a PE.")

    def test_zip_magic(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"PK\x03\x04" + b"\x00" * 200)

    def test_elf_magic(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"\x7fELF" + b"\x00" * 200)

    def test_pdf_magic(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"%PDF-1.4" + b"\x00" * 200)

    def test_mz_only(self) -> None:
        """MZ with no PE body — fails pefile validation."""
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ")

    def test_mz_plus_3_bytes(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ\x90\x00")

    def test_mz_plus_64_zeros(self) -> None:
        """Truncated DOS stub — pefile rejects invalid e_lfanew."""
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ" + b"\x00" * 64)

    def test_mz_plus_garbage(self) -> None:
        """MZ magic but random garbage body — pefile rejects invalid NT headers."""
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ" + b"\xde\xad\xbe\xef" * 200)

    def test_mz_plus_all_ff(self) -> None:
        with pytest.raises(MalformedPEError):
            build_raw_features(b"MZ" + b"\xff" * 500)

    def test_invalid_nt_signature(self) -> None:
        """MZ + e_lfanew=0x40 but 'PE\0\0' replaced with garbage."""
        import struct
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew points to next block
        # At offset 0x40, put garbage instead of PE\0\0
        payload = bytes(dos) + b"XX\x00\x00" + b"\x00" * 200
        with pytest.raises(MalformedPEError):
            build_raw_features(payload)

    def test_extract_ember_features_rejects_empty(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"")

    def test_extract_ember_features_rejects_non_pe(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"Not a PE file at all.")

    def test_extract_ember_features_rejects_mz_garbage(self) -> None:
        with pytest.raises(MalformedPEError):
            extract_ember_features(b"MZ" + b"\xff" * 500)


# ---------------------------------------------------------------------------
# 4. Valid PE extraction from a real PE fixture
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE fixture not available")
class TestRealPEExtraction:
    """windows-kill.exe from nodemon homebrew package — benign system utility, never executed."""

    def test_returns_2381_dimensional_vector(self) -> None:
        vec = extract_ember_features(_REAL_PE_BYTES)
        assert vec.shape == (EMBER_FEATURE_DIM,)

    def test_dtype_float32(self) -> None:
        vec = extract_ember_features(_REAL_PE_BYTES)
        assert vec.dtype == np.float32

    def test_all_values_finite(self) -> None:
        vec = extract_ember_features(_REAL_PE_BYTES)
        assert np.isfinite(vec).all()

    def test_nonzero_pe_features(self) -> None:
        """PE-group features (general, header, section, imports) must be non-trivially populated."""
        vec = extract_ember_features(_REAL_PE_BYTES)
        # General: bytes 616..625 — at minimum size and vsize should be non-zero
        general_offset = 256 + 256 + 104
        general = vec[general_offset:general_offset + 10]
        assert general[0] > 0, "size field should be non-zero"
        assert general[1] > 0, "vsize field should be non-zero (lief parsed OK)"

    def test_section_features_populated(self) -> None:
        """Section feature (index 628..882) must have n_sections > 0."""
        vec = extract_ember_features(_REAL_PE_BYTES)
        section_offset = 256 + 256 + 104 + 10 + 62
        n_sections = vec[section_offset]  # first element is len(sections)
        assert n_sections > 0, "n_sections should be > 0 for a real PE"

    def test_import_features_populated(self) -> None:
        """Import feature range must have at least some non-zero values."""
        vec = extract_ember_features(_REAL_PE_BYTES)
        import_offset = 256 + 256 + 104 + 10 + 62 + 255
        imports = vec[import_offset:import_offset + 1280]
        assert np.count_nonzero(imports) > 0, "imports should be populated for a real PE"

    def test_deterministic(self) -> None:
        v1 = extract_ember_features(_REAL_PE_BYTES)
        v2 = extract_ember_features(_REAL_PE_BYTES)
        np.testing.assert_array_equal(v1, v2)

    def test_raw_features_machine_string(self) -> None:
        """Machine field must be a non-empty string (e.g. 'AMD64')."""
        raw = build_raw_features(_REAL_PE_BYTES)
        machine = raw["header"]["coff"]["machine"]
        assert isinstance(machine, str) and machine != ""

    def test_raw_features_section_props_are_strings(self) -> None:
        raw = build_raw_features(_REAL_PE_BYTES)
        for sec in raw["section"]["sections"]:
            for prop in sec["props"]:
                assert isinstance(prop, str) and prop != ""

    def test_raw_features_general_size_matches(self) -> None:
        raw = build_raw_features(_REAL_PE_BYTES)
        assert raw["general"]["size"] == len(_REAL_PE_BYTES)

    def test_raw_features_imports_populated(self) -> None:
        raw = build_raw_features(_REAL_PE_BYTES)
        assert len(raw["imports"]) > 0

    def test_raw_features_datadirectories_is_list(self) -> None:
        raw = build_raw_features(_REAL_PE_BYTES)
        assert isinstance(raw["datadirectories"], list)
        assert len(raw["datadirectories"]) > 0

    @pytest.mark.skipif(not _JSONL_AVAILABLE, reason="EMBER JSONL not available")
    def test_real_pe_vector_differs_from_ember_jsonl_sample(self) -> None:
        """The real PE vector should differ from a JSONL record (different file)."""
        recs = _load_jsonl_records(1)
        jsonl_vec = vectorize_raw_features(recs[0])
        pe_vec = extract_ember_features(_REAL_PE_BYTES)
        assert not np.array_equal(pe_vec, jsonl_vec)


# ---------------------------------------------------------------------------
# 5. Model loading and inference
# ---------------------------------------------------------------------------

class TestModelLoader:
    def test_missing_artifact_not_ready(self, tmp_path: Path) -> None:
        m = load_model(tmp_path / "nonexistent.joblib")
        assert m.ready is False and m.estimator is None

    def test_corrupt_artifact_not_ready(self, tmp_path: Path) -> None:
        p = tmp_path / "corrupt.joblib"
        p.write_bytes(b"garbage")
        m = load_model(p)
        assert m.ready is False

    def test_wrong_features_not_ready(self, tmp_path: Path) -> None:
        clf = _make_mock_rf(n_features=100)
        p = tmp_path / "wrong.joblib"
        joblib.dump({"estimator": clf}, p)
        m = load_model(p)
        assert m.ready is False
        assert "2381" in m.load_error or "n_features" in m.load_error

    def test_dict_artifact_loads(self, tmp_path: Path) -> None:
        clf = _make_mock_rf()
        p = tmp_path / "ok.joblib"
        joblib.dump({"estimator": clf, "feature_names": [f"f_{i}" for i in range(EMBER_FEATURE_DIM)]}, p)
        m = load_model(p)
        assert m.ready is True and int(m.estimator.n_features_in_) == EMBER_FEATURE_DIM

    @pytest.mark.skipif(not _PRODUCTION_MODEL_EXISTS, reason="Production model absent")
    def test_production_model_ready(self) -> None:
        m = load_model(_PRODUCTION_MODEL_PATH)
        assert m.ready is True
        assert int(m.estimator.n_features_in_) == EMBER_FEATURE_DIM
        assert set(int(c) for c in m.estimator.classes_) == {0, 1}
        assert len(m.feature_names) == EMBER_FEATURE_DIM


class TestPredictor:
    def test_not_ready_raises(self) -> None:
        with pytest.raises(ModelNotReadyError):
            predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), LoadedModel(ready=False))

    def test_wrong_shape_raises(self) -> None:
        with pytest.raises(ValueError, match="shape"):
            predict(np.zeros(10, dtype=np.float32), _make_mock_model())

    def test_verdict_valid(self) -> None:
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), _make_mock_model())
        assert resp.verdict in ("benign", "malicious")

    def test_probability_in_bounds(self) -> None:
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), _make_mock_model())
        assert 0.0 <= resp.probability <= 1.0

    def test_risk_score_matches_probability(self) -> None:
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), _make_mock_model())
        assert resp.risk_score == int(round(resp.probability * 100))

    def test_top_features_at_most_5(self) -> None:
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), _make_mock_model())
        assert len(resp.top_features) <= 5

    def test_returns_analyze_response(self) -> None:
        resp = predict(np.zeros(EMBER_FEATURE_DIM, dtype=np.float32), _make_mock_model())
        assert isinstance(resp, AnalyzeResponse)

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE or not _PRODUCTION_MODEL_EXISTS,
                        reason="Requires real PE and production model")
    def test_real_pe_production_model(self) -> None:
        m = load_model(_PRODUCTION_MODEL_PATH)
        vec = extract_ember_features(_REAL_PE_BYTES)
        resp = predict(vec, m)
        # windows-kill.exe is a benign signed system utility — should be benign with low risk
        assert resp.verdict == "benign", f"Expected benign, got {resp.verdict} P={resp.probability}"
        assert resp.probability < 0.5
        assert resp.risk_score < 50


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

    def test_health_ok(self) -> None:
        assert self._client().get("/health").json()["status"] == "ok"

    def test_empty_upload_400(self) -> None:
        resp = self._client(_make_mock_model()).post(
            "/internal/analyze",
            files={"file": ("t.exe", b"", "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_non_pe_upload_400(self) -> None:
        resp = self._client(_make_mock_model()).post(
            "/internal/analyze",
            files={"file": ("t.txt", b"Hello, world!", "text/plain")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_mz_garbage_upload_400(self) -> None:
        """MZ+garbage now rejected by pefile validator — no OOD inference."""
        resp = self._client(_make_mock_model()).post(
            "/internal/analyze",
            files={"file": ("t.exe", b"MZ" + b"\xff" * 500, "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "malformed_pe"

    def test_model_not_ready_503(self) -> None:
        resp = self._client(LoadedModel(ready=False)).post(
            "/internal/analyze",
            files={"file": ("t.exe", _REAL_PE_BYTES if _REAL_PE_AVAILABLE else b"MZ", "application/octet-stream")},
        )
        # Either 503 (model not ready) or 400 (malformed PE — b"MZ" alone is invalid)
        assert resp.status_code in (400, 503)

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE not available")
    def test_real_pe_mock_model_200(self) -> None:
        resp = self._client(_make_mock_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        assert resp.status_code == 200, resp.text

    @pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE not available")
    def test_response_schema(self) -> None:
        resp = self._client(_make_mock_model()).post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        body = resp.json()
        assert "verdict" in body
        assert "probability" in body
        assert "risk_score" in body
        assert "top_features" in body
        assert body["verdict"] in ("benign", "malicious")
        assert 0.0 <= body["probability"] <= 1.0
        assert 0 <= body["risk_score"] <= 100
        assert len(body["top_features"]) <= 5

    @pytest.mark.skipif(
        not _REAL_PE_AVAILABLE or not _PRODUCTION_MODEL_EXISTS,
        reason="Requires real PE and production model",
    )
    def test_production_endpoint_real_pe(self) -> None:
        get_settings.cache_clear()
        from app.main import app
        m = load_model(_PRODUCTION_MODEL_PATH)
        with TestClient(app) as client:
            app.state.loaded_model = m
            resp = client.post(
                "/internal/analyze",
                files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "benign"
        assert body["probability"] < 0.5
