"""
Riley — AI-Powered False Positive Slayer
FastAPI application entrypoint.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.config import settings
from app.core.exceptions import RileyException
from app.core.logging import get_logger, setup_logging
from app.database import create_all_tables

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("riley_starting", env=settings.APP_ENV)
    await create_all_tables()
    logger.info("riley_ready", docs="/docs")
    yield
    logger.info("riley_shutdown")


app = FastAPI(
    title="Riley — AI False Positive Slayer",
    description=(
        "Riley automatically identifies, tags, and suppresses false positives using "
        "AI pattern recognition and analyst feedback loops. "
        "Built for lean security teams that can't afford to drown in noise.\n\n"
        "**Key endpoints:**\n"
        "- `POST /api/v1/alerts` — submit alert for triage\n"
        "- `POST /api/v1/feedback/{id}` — record analyst verdict (drives learning)\n"
        "- `GET /api/v1/stats` — dashboard brag sheet\n"
        "- `POST /api/v1/simulate` — accuracy benchmark\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.APP_ENV == "development" else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request timing middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Process-Time-Ms"] = str(elapsed)
    logger.debug("request", method=request.method, path=request.url.path, ms=elapsed)
    return response

# ── Exception handlers ────────────────────────────────────────────────────────
@app.exception_handler(RileyException)
async def riley_exception_handler(request: Request, exc: RileyException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(api_router)


@app.get("/health", tags=["Health"], summary="Health check")
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "riley", "version": "1.0.0"}


@app.get("/", tags=["Health"], include_in_schema=False)
async def root() -> dict[str, str]:
    return {
        "message": "Riley is online. 🔪 Slaying false positives.",
        "docs": "/docs",
        "stats": "/api/v1/stats",
        "simulate": "/api/v1/simulate",
    }
