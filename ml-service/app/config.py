from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ML_SERVICE_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """ML-service configuration. Backend, database, and crypto settings live elsewhere."""

    model_config = SettingsConfigDict(
        env_file=ML_SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        env_prefix="ML_",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    model_path: Path = ML_SERVICE_ROOT / "models" / "ember_rf.joblib"
    ember_data_dir: Path = ML_SERVICE_ROOT / "data" / "ember2018"
    max_file_size_bytes: int = 50 * 1024 * 1024
    host: str = "127.0.0.1"
    port: int = 8000

    @property
    def resolved_model_path(self) -> Path:
        path = self.model_path
        if not path.is_absolute():
            path = ML_SERVICE_ROOT / path
        return path

    @property
    def resolved_ember_data_dir(self) -> Path:
        path = self.ember_data_dir
        if not path.is_absolute():
            path = ML_SERVICE_ROOT / path
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()
