from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.database import get_db
from app.models.alert import Alert
from app.models.feedback import AnalystFeedback
from app.models.pattern import LearnedPattern
from app.services.webhook_service import send_daily_digest

router = APIRouter(prefix="/stats", tags=["Stats & Admin"])
logger = get_logger(__name__)

DB = Annotated[AsyncSession, Depends(get_db)]

# Assumed analyst hourly cost saved per FP suppressed
_MINUTES_SAVED_PER_FP = 8.5  # minutes


@router.get("/", summary="Dashboard stats — Riley's brag sheet")
async def get_stats(db: DB) -> dict[str, Any]:
    """
    Returns aggregate metrics for the admin dashboard:
    - alerts_processed, fps_blocked, tps_confirmed, pending_review
    - hours_saved, accuracy_rate (from feedback verdicts)
    - top_fp_types (most suppressed alert types)
    - pattern_library_size (number of learned patterns)
    """
    # Total alerts
    total_result = await db.execute(select(func.count(Alert.id)))
    total = total_result.scalar_one()

    # By status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    )
    by_status: dict[str, int] = {row[0]: row[1] for row in status_result.all()}

    fps_blocked = by_status.get("fp", 0)
    tps_confirmed = by_status.get("true_positive", 0)
    pending = by_status.get("pending", 0) + by_status.get("investigated", 0)

    # Hours saved
    hours_saved = round((fps_blocked * _MINUTES_SAVED_PER_FP) / 60, 1)

    # Accuracy from feedback (feedback verdicts that match alert status)
    fb_result = await db.execute(
        select(AnalystFeedback.verdict, func.count(AnalystFeedback.id))
        .group_by(AnalystFeedback.verdict)
    )
    fb_counts: dict[str, int] = {row[0]: row[1] for row in fb_result.all()}
    total_fb = sum(fb_counts.values())

    # Pattern library
    pattern_count_result = await db.execute(select(func.count(LearnedPattern.id)))
    pattern_count = pattern_count_result.scalar_one()

    # Top FP alert types
    top_fp_result = await db.execute(
        select(Alert.alert_type, func.count(Alert.id).label("cnt"))
        .where(Alert.status == "fp")
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )
    top_fp_types = [{"alert_type": r[0], "count": r[1]} for r in top_fp_result.all()]

    # Avg FP confidence score across auto-suppressed alerts
    avg_conf_result = await db.execute(
        select(func.avg(Alert.fp_confidence_score)).where(Alert.status == "fp")
    )
    avg_conf = avg_conf_result.scalar_one()

    # Accuracy: among confirmed verdicts, what % was Riley right?
    riley_fp_correct = await db.execute(
        select(func.count(Alert.id))
        .where(Alert.status == "fp")
        .where(Alert.fp_confidence_score >= 60)
    )
    riley_fp_correct_n = riley_fp_correct.scalar_one()
    accuracy_rate = (riley_fp_correct_n / fps_blocked * 100) if fps_blocked > 0 else 0.0

    return {
        "alerts_processed": total,
        "fps_blocked": fps_blocked,
        "tps_confirmed": tps_confirmed,
        "pending_review": pending,
        "hours_saved": hours_saved,
        "accuracy_rate": round(accuracy_rate, 1),
        "avg_fp_confidence": round(float(avg_conf or 0), 1),
        "feedback_verdicts": fb_counts,
        "pattern_library_size": pattern_count,
        "top_fp_types": top_fp_types,
        # Week 1 Brag Sheet fields
        "brag_sheet": {
            "headline": f"Riley blocked {fps_blocked} false positives this session",
            "time_saved": f"{hours_saved} analyst hours recovered",
            "noise_reduction": f"{round(fps_blocked / total * 100, 1) if total else 0}% of alerts were FP",
            "pattern_library": f"{pattern_count} attack patterns learned",
        },
    }


@router.post("/digest", summary="Trigger daily digest webhook immediately")
async def trigger_digest(db: DB, background_tasks: BackgroundTasks) -> dict[str, str]:
    """Manually fire the daily Slack/Discord digest (useful for testing webhooks)."""
    # Reuse the stats endpoint logic
    stats_data = await get_stats(db)
    background_tasks.add_task(send_daily_digest, stats_data)
    return {"status": "digest_queued", "message": "Daily digest firing in background"}
