from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.pattern import LearnedPattern
from app.schemas.pattern import PatternOut

router = APIRouter(prefix="/patterns", tags=["Learned Patterns"])

DB = Annotated[AsyncSession, Depends(get_db)]


@router.get("/", response_model=list[PatternOut], summary="Browse Riley's pattern library")
async def list_patterns(
    db: DB,
    alert_type: str | None = Query(None),
    min_confidence: float | None = Query(None, ge=0, le=1),
    limit: int = Query(50, le=200),
) -> list[PatternOut]:
    """
    Returns all learned patterns sorted by confidence descending.
    Filter by alert_type or minimum confidence threshold.
    """
    q = select(LearnedPattern)
    if alert_type:
        q = q.where(LearnedPattern.alert_type == alert_type)
    if min_confidence is not None:
        q = q.where(LearnedPattern.pattern_confidence >= min_confidence)
    q = q.order_by(LearnedPattern.pattern_confidence.desc()).limit(limit)
    result = await db.execute(q)
    return [PatternOut.model_validate(p) for p in result.scalars().all()]
