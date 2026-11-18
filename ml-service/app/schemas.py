from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["benign", "malicious"]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model_ready: bool = Field(
        ...,
        description="True when the RF artifact is loaded and validated (n_features==2381, classes=={0,1}).",
    )


class TopFeature(BaseModel):
    feature: str = Field(..., min_length=1, description="EMBER-style feature name")
    importance: float = Field(..., ge=0.0, le=1.0, description="Relative contribution in [0, 1]")
    description: str = Field(..., min_length=1, description="Human-readable explanation")


class AnalyzeResponse(BaseModel):
    verdict: Verdict
    probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model probability that the file is malicious",
    )
    risk_score: int = Field(..., ge=0, le=100, description="Normalized risk score in [0, 100]")
    top_features: list[TopFeature] = Field(
        ...,
        max_length=5,
        description="Top contributing features with human-readable explanations",
    )


class ErrorResponse(BaseModel):
    error: str
    detail: str
