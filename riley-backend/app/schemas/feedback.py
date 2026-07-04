from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FeedbackCreate(BaseModel):
    analyst_id: int
    verdict: str = Field(..., examples=["fp", "true_positive"])
    comment: str | None = None


class FeedbackOut(BaseModel):
    id: int
    alert_id: int
    analyst_id: int
    verdict: str
    comment: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
