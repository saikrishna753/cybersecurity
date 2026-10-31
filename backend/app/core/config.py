"""Application configuration from environment variables (.env supported)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]   # .../backend
REPO_DIR = BACKEND_DIR.parent                        # repo root
DEFAULT_DATA_DIR = REPO_DIR / "data"


def _load_dotenv() -> None:  # pragma: no cover - convenience only
    env_path = REPO_DIR / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path)
        except Exception:
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(REPO_DIR / ".env"), extra="ignore")

    app_name: str = Field(default="AI-IDS", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    secret_key: str = Field(default="dev-insecure-secret-change-me", alias="APP_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="APP_JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=720, alias="APP_JWT_EXPIRE_MINUTES")

    database_url: str = Field(default="", alias="DATABASE_URL")
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000", alias="CORS_ORIGINS"
    )

    upload_dir: str = Field(default=str(DEFAULT_DATA_DIR / "uploads"), alias="UPLOAD_DIR")
    artifact_dir: str = Field(default=str(BACKEND_DIR / "artifacts"), alias="ARTIFACT_DIR")
    max_upload_mb: int = Field(default=200, alias="MAX_UPLOAD_MB")

    bootstrap_admin_email: str = Field(
        default="admin@ai-ids.local", alias="BOOTSTRAP_ADMIN_EMAIL"
    )
    bootstrap_admin_password: str = Field(
        default="ChangeMe!123", alias="BOOTSTRAP_ADMIN_PASSWORD"
    )

    live_capture_enabled: bool = Field(default=True, alias="LIVE_CAPTURE_ENABLED")
    live_capture_batch_size: int = Field(default=200, alias="LIVE_CAPTURE_BATCH_SIZE")
    live_capture_queue_max: int = Field(default=1000, alias="LIVE_CAPTURE_QUEUE_MAX")

    ti_provider: str = Field(default="none", alias="TI_PROVIDER")
    ti_api_key: str = Field(default="", alias="TI_API_KEY")
    ti_cache_ttl_seconds: int = Field(default=86400, alias="TI_CACHE_TTL_SECONDS")

    smtp_enabled: bool = Field(default=False, alias="SMTP_ENABLED")
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="alerts@ai-ids.local", alias="SMTP_FROM")

    rate_limit_per_minute: int = Field(default=300, alias="RATE_LIMIT_PER_MINUTE")

    # ------------------------------------------------------------------ #
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            url = self.database_url
            if url.startswith("sqlite:///") and "://" in url[len("sqlite:///"):]:
                return url
            if url.startswith("sqlite:///"):
                p = Path(url[len("sqlite:///"):])
                if not p.is_absolute():
                    p = DEFAULT_DATA_DIR / p.name
                p.parent.mkdir(parents=True, exist_ok=True)
                return f"sqlite:///{p}"
            return url
        DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEFAULT_DATA_DIR / 'ai_ids.db'}"

    @property
    def models_dir(self) -> Path:
        p = Path(self.artifact_dir) / "models"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def reports_dir(self) -> Path:
        p = Path(self.artifact_dir) / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def upload_path(self) -> Path:
        p = Path(self.upload_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    _load_dotenv()
    return Settings()
