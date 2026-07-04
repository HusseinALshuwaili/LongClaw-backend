from __future__ import annotations

import os
import re
import ssl
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


def _prepare_db_url(url: str):
    """Strip asyncpg-incompatible params and return (clean_url, connect_args)."""
    # Fix driver prefix
    url = re.sub(r'^postgres(ql)?://', 'postgresql+asyncpg://', url)

    # Remove params asyncpg rejects
    for param in ('sslmode', 'channel_binding', 'options'):
        url = re.sub(rf'[?&]{param}=[^&]*', '', url)

    # Clean up dangling punctuation
    url = re.sub(r'\?&+', '?', url)
    url = re.sub(r'[?&]+$', '', url)

    # Enable SSL for any remote host (Neon requires it)
    connect_args: dict = {}
    is_remote = 'localhost' not in url and '127.0.0.1' not in url
    if is_remote:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        connect_args['ssl'] = ctx

    return url, connect_args


# Read directly from env so this works regardless of config.py validator state
_raw_url = os.environ.get(
    'DATABASE_URL',
    'postgresql+asyncpg://riley:riley_secret@localhost:5432/riley_db'
)
_db_url, _connect_args = _prepare_db_url(_raw_url)

engine = create_async_engine(
    _db_url,
    echo=os.environ.get('APP_ENV', 'development') == 'development',
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    connect_args=_connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_all_tables() -> None:
    from app.models import alert, feedback, pattern, user  # noqa: F401
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        # Tables may already exist (e.g. on restart) — that's fine
        if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
            pass
        else:
            raise
