from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.id"), nullable=False, index=True
    )
    analyst_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    # "fp" | "true_positive"
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    alert: Mapped["Alert"] = relationship("Alert", back_populates="feedback")  # noqa: F821
    analyst: Mapped["User"] = relationship("User", back_populates="feedback")  # noqa: F821
