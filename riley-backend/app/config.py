from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Database ────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://riley:riley_secret@localhost:5432/riley_db"

    # ── Redis ───────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379"

    # ── OpenAI ─────────────────────────────────────────────────
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    # ── Webhooks ────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # ── App ─────────────────────────────────────────────────────
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "change-me-in-production"

    # ── FP Engine ───────────────────────────────────────────────
    FP_AUTO_SUPPRESS_THRESHOLD: float = 85.0   # auto-close as FP
    FP_LOW_PRIORITY_THRESHOLD: float = 60.0    # tag for review queue

    # ── Rate Limiting ───────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 100


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
