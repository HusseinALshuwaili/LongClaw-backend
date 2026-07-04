from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import http_404, http_422
from app.core.logging import get_logger
from app.database import get_db
from app.models.alert import Alert
from app.models.feedback import AnalystFeedback
from app.models.user import User
from app.schemas.feedback import FeedbackCreate, FeedbackOut
from app.services.pattern_engine import extract_signature, upsert_pattern

router = APIRouter(prefix="/feedback", tags=["Feedback"])
logger = get_logger(__name__)

DB = Annotated[AsyncSession, Depends(get_db)]

VALID_VERDICTS = {"fp", "true_positive"}


@router.post("/{alert_id}", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED,
             summary="Submit analyst verdict on an alert")
async def submit_feedback(
    alert_id: int,
    body: FeedbackCreate,
    db: DB,
) -> FeedbackOut:
    """
    Record analyst verdict (fp / true_positive) for an alert.

    **Immediately triggers:**
    1. Alert status update
    2. Normalised signature extraction
    3. LearnedPatterns upsert (increments confidence)
    4. Pattern weight recalculation
    """
    if body.verdict not in VALID_VERDICTS:
        raise http_422(f"verdict must be one of: {sorted(VALID_VERDICTS)}")

    # Verify alert exists
    alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert: Alert | None = alert_result.scalar_one_or_none()
    if not alert:
        raise http_404(f"Alert {alert_id} not found")

    # Verify analyst exists
    user_result = await db.execute(select(User).where(User.id == body.analyst_id))
    if not user_result.scalar_one_or_none():
        raise http_404(f"User {body.analyst_id} not found")

    # 1. Record feedback
    fb = AnalystFeedback(
        alert_id=alert_id,
        analyst_id=body.analyst_id,
        verdict=body.verdict,
        comment=body.comment,
    )
    db.add(fb)

    # 2. Update alert status
    alert.status = "fp" if body.verdict == "fp" else "true_positive"

    # 3. Extract signature (use existing if available, else re-derive)
    signature = alert.normalized_signature or extract_signature(
        alert.alert_type, alert.raw_data
    )

    # 4. Upsert into LearnedPatterns → self-improving feedback loop
    pattern = await upsert_pattern(
        alert_type=alert.alert_type,
        signature=signature,
        verdict=body.verdict,
        db=db,
    )

    await db.commit()
    await db.refresh(fb)

    logger.info(
        "feedback_recorded",
        alert_id=alert_id,
        verdict=body.verdict,
        pattern_id=pattern.id,
        new_confidence=pattern.pattern_confidence,
    )
    return FeedbackOut.model_validate(fb)


@router.get("/{alert_id}", response_model=list[FeedbackOut],
            summary="Get all feedback for an alert")
async def get_feedback(alert_id: int, db: DB) -> list[FeedbackOut]:
    result = await db.execute(
        select(AnalystFeedback)
        .where(AnalystFeedback.alert_id == alert_id)
        .order_by(AnalystFeedback.created_at.desc())
    )
    return [FeedbackOut.model_validate(fb) for fb in result.scalars().all()]
