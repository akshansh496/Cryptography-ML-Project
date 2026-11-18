"""Tests for GET /health endpoint."""

from fastapi import status


def test_health_returns_ok_status(client) -> None:
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "ok"


def test_health_includes_model_ready(client) -> None:
    """model_ready must be present in the health response.

    The Node.js backend uses this field to determine whether the ML service
    has finished loading its artifact and is ready for inference, without
    making a speculative POST /internal/analyze request.
    """
    response = client.get("/health")
    body = response.json()
    assert "model_ready" in body
    assert isinstance(body["model_ready"], bool)


def test_health_model_ready_true_when_artifact_present(client) -> None:
    """When the production artifact is present and valid, model_ready is True."""
    from pathlib import Path
    from app.config import ML_SERVICE_ROOT

    model_path = ML_SERVICE_ROOT / "models" / "ember_rf.joblib"
    if not model_path.exists():
        import pytest
        pytest.skip("Production model artifact not present")

    response = client.get("/health")
    assert response.json()["model_ready"] is True
