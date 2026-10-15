"""Malware classification inference against the loaded Random Forest."""

from app.inference.predictor import ModelNotReadyError, predict

__all__ = ["ModelNotReadyError", "predict"]
