from __future__ import annotations

import ssl
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


def _make_engine():
    url = settings.DATABASE_URL
    # For Neon / remote Postgres, enable SSL via connect_args
    # and strip sslmode from URL (asyncpg handles SSL separately)
    connect_args = {}
    if "neon.tech" in url or ("localhost" not in url and "127.0.0.1" not in url):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        connect_args = {"ssl": ctx}

    return create_async_engine(
        url,
        echo=settings.APP_ENV == "development",
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


engine = _make_engine()

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
    async with engine.begin() as conn:
        from app.models import alert, feedback, pattern, user  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
