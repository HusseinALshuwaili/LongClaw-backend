from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _clean_db_url(v: str) -> str:
    """Normalize any postgres URL for asyncpg + SQLAlchemy."""
    # Ensure asyncpg driver
    if v.startswith('postgresql://') or v.startswith('postgres://'):
        v = re.sub(r'^postgres(ql)?://', 'postgresql+asyncpg://', v)

    # Strip query params asyncpg doesn't support
    bad_params = ['sslmode', 'channel_binding', 'options']
    for param in bad_params:
        v = re.sub(rf'[?&]{param}=[^&]*', lambda m: '' if m.group().startswith('?') else '', v)

    # Clean up dangling ? or &
    v = re.sub(r'\?&', '?', v)
    v = re.sub(r'[?&]$', '', v)
    return v


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://riley:riley_secret@localhost:5432/riley_db"

    @field_validator('DATABASE_URL', mode='before')
    @classmethod
    def fix_database_url(cls, v: str) -> str:
        return _clean_db_url(v)

    REDIS_URL: str = "redis://localhost:6379"

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"

    GROQ_API_KEY: Optional[str] = None

    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None

    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "change-me-in-production"

    FP_AUTO_SUPPRESS_THRESHOLD: float = 85.0
    FP_LOW_PRIORITY_THRESHOLD: float = 60.0
    RATE_LIMIT_PER_MINUTE: int = 100


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
