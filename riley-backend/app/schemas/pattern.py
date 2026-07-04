from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class PatternOut(BaseModel):
    id: int
    alert_type: str
    pattern_signature: dict[str, Any]
    pattern_confidence: float
    occurrences: int
    fp_count: int
    tp_count: int
    last_updated: datetime

    model_config = {"from_attributes": True}
