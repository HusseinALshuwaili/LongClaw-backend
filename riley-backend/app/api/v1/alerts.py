from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import http_404, http_409
from app.core.logging import get_logger
from app.database import AsyncSessionLocal, get_db
from app.models.alert import Alert
from app.models.feedback import AnalystFeedback
from app.schemas.alert import AlertCreate, AlertFilter, AlertListOut, AlertOut
from app.services.enrichment import enrich_alert
from app.services.fp_scorer import score_alert
from app.services.pattern_engine import extract_signature
from app.services.webhook_service import notify_auto_suppressed

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = get_logger(__name__)

DB = Annotated[AsyncSession, Depends(get_db)]


# ── Helper ────────────────────────────────────────────────────────────────────

async def _run_riley_pipeline(alert_id: int) -> None:
    """
    Background task: enrich → score → update alert.
    Uses its own session so it runs independently of the request session.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if alert is None:
            logger.error("pipeline_alert_not_found", alert_id=alert_id)
            return

        try:
            # 1. Enrich
            enrichment = await enrich_alert(alert.raw_data)
            alert.enrichment_data = enrichment

            # 2. Extract normalised signature
            signature = extract_signature(alert.alert_type, alert.raw_data)
            alert.normalized_signature = signature

            # 3. Collect existing analyst comments for LLM context
            fb_result = await db.execute(
                select(AnalystFeedback.comment)
                .where(AnalystFeedback.alert_id == alert_id)
            )
            comments = [c for c in fb_result.scalars().all() if c]

            # 4. Score
            scored = await score_alert(
                alert_type=alert.alert_type,
                severity=alert.severity,
                raw_data=alert.raw_data,
                enrichment=enrichment,
                signature=signature,
                created_at=alert.created_at,
                analyst_comments=comments,
                db=db,
            )

            alert.fp_confidence_score = scored.fp_confidence
            alert.fp_reason = scored.reason
            alert.suggested_action = scored.suggested_action

            # 5. Apply threshold action
            if scored.action == "AUTO_SUPPRESS":
                alert.status = "fp"
                alert.tags = list(set(alert.tags or []) | {"auto_suppressed"})
                await db.commit()
                await notify_auto_suppressed(alert.id, alert.alert_type, scored.fp_confidence)
            elif scored.action == "LOW_PRIORITY_REVIEW":
                alert.status = "pending"
                alert.tags = list(set(alert.tags or []) | {"low_priority_review"})
            else:
                alert.status = "pending"
                alert.tags = list(set(alert.tags or []) | {"escalate"})

            await db.commit()
            logger.info("riley_pipeline_complete", alert_id=alert_id,
                        score=scored.fp_confidence, action=scored.action)

        except Exception as exc:
            logger.error("riley_pipeline_error", alert_id=alert_id, error=str(exc))
            await db.rollback()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/", response_model=AlertOut, status_code=status.HTTP_202_ACCEPTED,
             summary="Submit a new alert for Riley to triage")
async def create_alert(
    body: AlertCreate,
    background_tasks: BackgroundTasks,
    db: DB,
) -> AlertOut:
    """
    Submit a raw alert. Riley enriches and scores it asynchronously.
    Returns the alert row immediately; check back via GET /alerts/{id} for the score.
    """
    # Check for duplicate external_id
    if body.external_id:
        exists = await db.execute(
            select(Alert).where(Alert.external_id == body.external_id)
        )
        if exists.scalar_one_or_none():
            raise http_409(f"Alert with external_id={body.external_id} already exists")

    alert = Alert(
        external_id=body.external_id or str(uuid.uuid4()),
        source_system=body.source_system,
        alert_type=body.alert_type,
        severity=body.severity,
        raw_data=body.raw_data,
        status="pending",
        tags=[],
    )
    db.add(alert)
    await db.flush()  # get ID before background task
    await db.refresh(alert)
    alert_id = alert.id

    # Fire-and-forget: run Riley pipeline in background
    background_tasks.add_task(_run_riley_pipeline, alert_id)

    await db.commit()
    logger.info("alert_created", id=alert_id, source=body.source_system, type=body.alert_type)
    return AlertOut.model_validate(alert)


@router.get("/", response_model=AlertListOut, summary="List alerts with optional filters")
async def list_alerts(
    db: DB,
    status: str | None = Query(None),
    severity: str | None = Query(None),
    source_system: str | None = Query(None),
    min_confidence: float | None = Query(None, ge=0, le=100),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
) -> AlertListOut:
    q = select(Alert)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if source_system:
        q = q.where(Alert.source_system == source_system)
    if min_confidence is not None:
        q = q.where(Alert.fp_confidence_score >= min_confidence)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    items = [AlertOut.model_validate(a) for a in result.scalars().all()]
    return AlertListOut(total=total, items=items)


@router.get("/{alert_id}", response_model=AlertOut, summary="Get a single alert by ID")
async def get_alert(alert_id: int, db: DB) -> AlertOut:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise http_404(f"Alert {alert_id} not found")
    return AlertOut.model_validate(alert)


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT,
               response_model=None,
               summary="Delete an alert (admin use)")
async def delete_alert(alert_id: int, db: DB) -> None:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise http_404(f"Alert {alert_id} not found")
    await db.delete(alert)
    await db.commit()
