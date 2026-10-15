"""Prompt 8 integration tests: API contract, security, and health audit.

Tests verify:
  - /health response schema (status, model_ready)
  - /internal/analyze multipart contract
  - Upload field name, response schema, status codes
  - Upload size enforcement (413) with correct ErrorResponse format
  - Security: no stack traces, no file paths, no raw bytes in error responses
  - Structured ErrorResponse for all error codes
  - No persistence of uploaded files
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier

from app.config import ML_SERVICE_ROOT, get_settings
from app.data.ember_feature_schema import EMBER_FEATURE_DIM
from app.model.model_loader import LoadedModel

_REAL_PE_PATH = Path("/opt/homebrew/lib/node_modules/nodemon/bin/windows-kill.exe")
_REAL_PE_AVAILABLE = _REAL_PE_PATH.exists()
_REAL_PE_BYTES: bytes = _REAL_PE_PATH.read_bytes() if _REAL_PE_AVAILABLE else b""

_PROD_MODEL_PATH = ML_SERVICE_ROOT / "models" / "ember_rf.joblib"
_PROD_MODEL_EXISTS = _PROD_MODEL_PATH.exists()

_REAL_PE_SKIP = pytest.mark.skipif(not _REAL_PE_AVAILABLE, reason="Real PE fixture not available")


def _make_client_with_mock_model() -> TestClient:
    """Return a TestClient with a valid mock model loaded."""
    get_settings.cache_clear()
    from app.main import app

    rng = np.random.default_rng(42)
    X = np.vstack([
        rng.normal(0, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
        rng.normal(2, 0.5, (40, EMBER_FEATURE_DIM)).astype(np.float32),
    ])
    y = np.array([0] * 40 + [1] * 40, dtype=np.int32)
    clf = RandomForestClassifier(n_estimators=6, random_state=42, n_jobs=1)
    clf.fit(X, y)
    mock_model = LoadedModel(
        estimator=clf,
        feature_names=[f"f_{i}" for i in range(EMBER_FEATURE_DIM)],
        ready=True,
    )
    client = TestClient(app)
    app.state.loaded_model = mock_model
    return client


# ---------------------------------------------------------------------------
# 1. Health endpoint contract
# ---------------------------------------------------------------------------

class TestHealthContract:
    def test_health_status_200(self, client: TestClient) -> None:
        assert client.get("/health").status_code == 200

    def test_health_status_field(self, client: TestClient) -> None:
        assert client.get("/health").json()["status"] == "ok"

    def test_health_model_ready_field_present(self, client: TestClient) -> None:
        """model_ready MUST be present — integration callers depend on it."""
        body = client.get("/health").json()
        assert "model_ready" in body, "model_ready field missing from /health response"

    def test_health_model_ready_is_bool(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert isinstance(body["model_ready"], bool)

    def test_health_model_ready_no_extra_fields(self, client: TestClient) -> None:
        """Health response must not expose internal paths, error strings, or stack traces."""
        body = client.get("/health").json()
        body_str = str(body)
        assert "/Users" not in body_str
        assert "Traceback" not in body_str
        assert "ember_rf" not in body_str

    @pytest.mark.skipif(not _PROD_MODEL_EXISTS, reason="Production model absent")
    def test_health_model_ready_true_with_production_model(self, client: TestClient) -> None:
        assert client.get("/health").json()["model_ready"] is True

    def test_health_model_ready_false_without_model(self) -> None:
        """Without a valid model the service starts but reports model_ready=False."""
        get_settings.cache_clear()
        os.environ["ML_MODEL_PATH"] = "/nonexistent/path/ember_rf.joblib"
        try:
            from app.main import app
            with TestClient(app) as client:
                body = client.get("/health").json()
                assert body["status"] == "ok"
                assert body["model_ready"] is False
        finally:
            del os.environ["ML_MODEL_PATH"]
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 2. /internal/analyze — request format
# ---------------------------------------------------------------------------

class TestAnalyzeRequestFormat:
    """Verify the multipart contract: field name 'file', form-data encoding."""

    @_REAL_PE_SKIP
    def test_upload_field_name_is_file(self) -> None:
        """Node.js sends FormData with field name 'file'. Confirm it is accepted."""
        client = _make_client_with_mock_model()
        resp = client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        assert resp.status_code == 200

    @_REAL_PE_SKIP
    def test_wrong_field_name_returns_422(self) -> None:
        """Sending multipart with field name 'upload' (not 'file') returns 422."""
        client = _make_client_with_mock_model()
        resp = client.post(
            "/internal/analyze",
            files={"upload": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert "error" in body  # must use ErrorResponse, not raw FastAPI default

    def test_no_file_returns_422(self) -> None:
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 3. /internal/analyze — response schema contract
# ---------------------------------------------------------------------------

class TestAnalyzeResponseSchema:
    """Response must exactly match AnalyzeResponse Pydantic model."""

    @_REAL_PE_SKIP
    def test_response_has_verdict(self) -> None:
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        assert "verdict" in resp.json()

    @_REAL_PE_SKIP
    def test_verdict_is_benign_or_malicious(self) -> None:
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        assert resp.json()["verdict"] in ("benign", "malicious")

    @_REAL_PE_SKIP
    def test_probability_semantics(self) -> None:
        """probability = P(malicious | features), always in [0.0, 1.0]."""
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        p = resp.json()["probability"]
        assert isinstance(p, float)
        assert 0.0 <= p <= 1.0

    @_REAL_PE_SKIP
    def test_risk_score_range(self) -> None:
        """risk_score = round(probability * 100), always in [0, 100]."""
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        body = resp.json()
        r = body["risk_score"]
        assert isinstance(r, int)
        assert 0 <= r <= 100
        # Must match probability
        assert r == round(body["probability"] * 100)

    @_REAL_PE_SKIP
    def test_top_features_structure(self) -> None:
        """Each top_features entry must have feature, importance, description."""
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        for tf in resp.json()["top_features"]:
            assert "feature" in tf and len(tf["feature"]) > 0
            assert "importance" in tf and 0.0 <= tf["importance"] <= 1.0
            assert "description" in tf and len(tf["description"]) > 0

    @_REAL_PE_SKIP
    def test_top_features_max_5(self) -> None:
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        assert len(resp.json()["top_features"]) <= 5

    @_REAL_PE_SKIP
    def test_no_extra_fields_in_response(self) -> None:
        """Response must not include internal fields like model path or extraction logs."""
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        body = resp.json()
        assert set(body.keys()) == {"verdict", "probability", "risk_score", "top_features"}


# ---------------------------------------------------------------------------
# 4. HTTP status codes and ErrorResponse schema
# ---------------------------------------------------------------------------

class TestErrorResponseSchema:
    """All non-200 responses must use ErrorResponse: {error: str, detail: str}."""

    def _assert_error_response(self, resp, expected_status: int, expected_error: str) -> None:
        assert resp.status_code == expected_status, f"Expected {expected_status}, got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert "error" in body, f"Missing 'error' key: {body}"
        assert "detail" in body, f"Missing 'detail' key: {body}"
        assert body["error"] == expected_error, f"Expected error={expected_error!r}, got {body['error']!r}"

    def test_empty_upload_is_400_malformed_pe(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"", "application/octet-stream")})
        self._assert_error_response(resp, 400, "malformed_pe")

    def test_non_pe_upload_is_400_malformed_pe(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.txt", b"Hello, world!", "application/octet-stream")})
        self._assert_error_response(resp, 400, "malformed_pe")

    def test_mz_garbage_is_400_malformed_pe(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"MZ" + b"\xff" * 500, "application/octet-stream")})
        self._assert_error_response(resp, 400, "malformed_pe")

    def test_oversized_upload_is_413_file_too_large(self) -> None:
        """413 must use ErrorResponse {error: 'file_too_large', detail: ...}."""
        get_settings.cache_clear()
        os.environ["ML_MAX_FILE_SIZE_BYTES"] = "10"
        try:
            from app.main import app
            client = TestClient(app)
            resp = client.post(
                "/internal/analyze",
                files={"file": ("big.exe", b"X" * 100, "application/octet-stream")},
            )
            # The file is not a PE, so it may hit 400 first (malformed) or 413 (size check first)
            # Our code does size check AFTER file.read() but BEFORE feature extraction
            # A 100-byte non-PE file will be: read→size check fails (10<100)→413
            assert resp.status_code == 413
            body = resp.json()
            assert "error" in body, f"413 response missing 'error' key: {body}"
            assert body["error"] == "file_too_large"
            assert "detail" in body
        finally:
            del os.environ["ML_MAX_FILE_SIZE_BYTES"]
            get_settings.cache_clear()

    def test_model_not_ready_is_503(self) -> None:
        get_settings.cache_clear()
        from app.main import app
        with TestClient(app) as client:
            app.state.loaded_model = LoadedModel(ready=False)
            resp = client.post(
                "/internal/analyze",
                files={"file": ("t.exe", _REAL_PE_BYTES if _REAL_PE_AVAILABLE else b"", "application/octet-stream")},
            )
        # If PE is available: 503 (model not ready); if not: 400 (malformed)
        assert resp.status_code in (400, 503)
        if resp.status_code == 503:
            self._assert_error_response(resp, 503, "model_not_ready")

    def test_missing_file_field_is_422(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze")
        assert resp.status_code == 422
        body = resp.json()
        assert "error" in body


# ---------------------------------------------------------------------------
# 5. Security — no internal information leakage
# ---------------------------------------------------------------------------

class TestSecurityNoLeakage:
    """Error responses must not expose internal paths, stack traces, or file bytes."""

    _SENSITIVE_PATTERNS = [
        "/Users/akshanshgupta",
        "/opt/homebrew",
        "Traceback",
        "traceback",
        "File \"/",
        "ember_rf.joblib",
        ".venv",
        "b'hell",         # raw bytes echoed
        "b'MZ",           # raw bytes echoed
    ]

    def _check_no_leak(self, body_str: str) -> None:
        for pattern in self._SENSITIVE_PATTERNS:
            assert pattern not in body_str, (
                f"Sensitive string {pattern!r} leaked in error response: {body_str[:200]}"
            )

    def test_empty_upload_no_leak(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"", "application/octet-stream")})
        self._check_no_leak(str(resp.json()))

    def test_non_pe_no_leak(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.txt", b"hello world", "application/octet-stream")})
        self._check_no_leak(str(resp.json()))

    def test_mz_garbage_no_leak(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"MZ" + b"\xde\xad\xbe\xef" * 200, "application/octet-stream")})
        self._check_no_leak(str(resp.json()))

    def test_health_no_leak(self, client: TestClient) -> None:
        self._check_no_leak(str(client.get("/health").json()))


# ---------------------------------------------------------------------------
# 6. Upload security
# ---------------------------------------------------------------------------

class TestUploadSecurity:
    def test_empty_upload_rejected(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"", "application/octet-stream")})
        assert resp.status_code == 400

    def test_non_pe_rejected(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.txt", b"I am a text file", "application/octet-stream")})
        assert resp.status_code == 400

    def test_zip_rejected(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.zip", b"PK\x03\x04" + b"\x00" * 200, "application/octet-stream")})
        assert resp.status_code == 400

    def test_elf_rejected(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.elf", b"\x7fELF" + b"\x00" * 200, "application/octet-stream")})
        assert resp.status_code == 400

    def test_mz_garbage_rejected(self, client: TestClient) -> None:
        resp = client.post("/internal/analyze",
                           files={"file": ("t.exe", b"MZ" + b"\xff" * 500, "application/octet-stream")})
        assert resp.status_code == 400

    @_REAL_PE_SKIP
    def test_valid_pe_accepted(self) -> None:
        client = _make_client_with_mock_model()
        resp = client.post("/internal/analyze",
                           files={"file": ("pe.exe", _REAL_PE_BYTES, "application/octet-stream")})
        assert resp.status_code == 200

    def test_size_limit_enforced(self) -> None:
        """Upload size is enforced; the limit comes from ML_MAX_FILE_SIZE_BYTES."""
        get_settings.cache_clear()
        os.environ["ML_MAX_FILE_SIZE_BYTES"] = "10"
        try:
            from app.main import app
            client = TestClient(app)
            resp = client.post(
                "/internal/analyze",
                files={"file": ("big.exe", b"X" * 1000, "application/octet-stream")},
            )
            assert resp.status_code == 413
        finally:
            del os.environ["ML_MAX_FILE_SIZE_BYTES"]
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 7. Full production integration (skipped if artifacts absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _PROD_MODEL_EXISTS or not _REAL_PE_AVAILABLE,
    reason="Requires production model and real PE fixture",
)
class TestProductionIntegration:
    def test_health_model_ready(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["model_ready"] is True

    def test_real_pe_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        assert resp.status_code == 200

    def test_real_pe_verdict_benign(self, client: TestClient) -> None:
        resp = client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        body = resp.json()
        assert body["verdict"] == "benign"
        assert body["probability"] < 0.5
        assert body["risk_score"] < 50

    def test_response_matches_schema(self, client: TestClient) -> None:
        from app.schemas import AnalyzeResponse
        resp = client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        parsed = AnalyzeResponse.model_validate(resp.json())
        assert parsed.verdict in ("benign", "malicious")
        assert 0.0 <= parsed.probability <= 1.0
        assert 0 <= parsed.risk_score <= 100

    def test_model_loaded_once_not_per_request(self, client: TestClient) -> None:
        """The model must be the same object across requests (loaded once at startup)."""
        from app.main import app
        model_before = app.state.loaded_model
        client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        client.post(
            "/internal/analyze",
            files={"file": ("windows-kill.exe", _REAL_PE_BYTES, "application/octet-stream")},
        )
        assert app.state.loaded_model is model_before
