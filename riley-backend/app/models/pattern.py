from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LearnedPattern(Base):
    __tablename__ = "learned_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    pattern_signature: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Confidence is recalculated on every feedback upsert:
    # confidence = fp_count / (fp_count + tp_count)
    pattern_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    fp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
