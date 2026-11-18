import pytest
from pydantic import ValidationError

from app.schemas import AnalyzeResponse, ErrorResponse, TopFeature


def test_analyze_response_accepts_contract_payload() -> None:
    payload = AnalyzeResponse(
        verdict="benign",
        probability=0.12,
        risk_score=12,
        top_features=[
            TopFeature(
                feature="section_entropy_text",
                importance=0.31,
                description="Entropy of the .text section; high values can indicate packing or obfuscation.",
            )
        ],
    )
    dumped = payload.model_dump()
    assert dumped["verdict"] == "benign"
    assert dumped["probability"] == 0.12
    assert dumped["risk_score"] == 12
    assert len(dumped["top_features"]) == 1
    assert dumped["top_features"][0]["feature"] == "section_entropy_text"


def test_analyze_response_rejects_invalid_verdict() -> None:
    with pytest.raises(ValidationError):
        AnalyzeResponse(verdict="unknown", probability=0.5, risk_score=50, top_features=[])


def test_analyze_response_rejects_out_of_range_risk_score() -> None:
    with pytest.raises(ValidationError):
        AnalyzeResponse(verdict="malicious", probability=0.9, risk_score=101, top_features=[])


def test_error_response_represents_malformed_input() -> None:
    error = ErrorResponse(
        error="malformed_pe",
        detail="File is not a valid PE (missing MZ DOS stub magic).",
    )
    assert error.error == "malformed_pe"
    assert "MZ" in error.detail
