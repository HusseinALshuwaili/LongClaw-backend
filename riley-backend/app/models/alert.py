from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    external_id: Mapped[str | None] = mapped_column(String, unique=True, index=True)

    # Source
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    # Payload
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    enrichment_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    normalized_signature: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    # Classification
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending", index=True
    )  # pending | investigated | fp | true_positive
    fp_confidence_score: Mapped[float | None] = mapped_column(Float)
    fp_reason: Mapped[str | None] = mapped_column(String(512))
    suggested_action: Mapped[str | None] = mapped_column(String(256))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now()
    )

    # Relationships
    feedback: Mapped[list["AnalystFeedback"]] = relationship(  # noqa: F821
        "AnalystFeedback", back_populates="alert", lazy="selectin"
    )
