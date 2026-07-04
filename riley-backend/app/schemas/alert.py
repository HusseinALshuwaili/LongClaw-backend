from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    external_id: str | None = None
    source_system: str = Field(..., examples=["splunk", "sentinel", "crowdstrike"])
    alert_type: str = Field(..., examples=["powershell_execution", "lateral_movement"])
    severity: str = Field(default="medium", examples=["critical", "high", "medium", "low", "info"])
    raw_data: dict[str, Any] = Field(..., description="Full raw alert payload")


class AlertOut(BaseModel):
    id: int
    external_id: str | None
    source_system: str
    alert_type: str
    severity: str
    status: str
    fp_confidence_score: float | None
    fp_reason: str | None
    suggested_action: str | None
    tags: list[str]
    enrichment_data: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class AlertListOut(BaseModel):
    total: int
    items: list[AlertOut]


class AlertFilter(BaseModel):
    status: str | None = None
    severity: str | None = None
    source_system: str | None = None
    min_confidence: float | None = None
    limit: int = Field(default=50, le=200)
    offset: int = Field(default=0, ge=0)
