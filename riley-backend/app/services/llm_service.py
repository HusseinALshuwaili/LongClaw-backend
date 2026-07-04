"""
LLM Service — thin adapter over the Claude ReAct agent.

Keeps the LLMScore interface that fp_scorer.py expects while delegating
all real reasoning to react_agent.run_react_agent().
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.react_agent import ReActVerdict, run_react_agent

logger = get_logger(__name__)


class LLMScore:
    """Structured result returned to fp_scorer.py."""

    def __init__(
        self,
        score: float,
        reason: str,
        suggested_action: str,
        evidence: list[str] | None = None,
        tool_steps: int = 0,
        model_used: str = "unknown",
    ) -> None:
        self.score = score
        self.reason = reason
        self.suggested_action = suggested_action
        self.evidence = evidence or []
        self.tool_steps = tool_steps
        self.model_used = model_used

    @classmethod
    def from_verdict(cls, v: ReActVerdict) -> "LLMScore":
        return cls(
            score=v.score,
            reason=v.reason,
            suggested_action=v.action_label,
            evidence=v.evidence,
            tool_steps=v.tool_steps,
            model_used=v.model_used,
        )


async def score_with_llm(
    alert_type: str,
    severity: str,
    raw_data: dict[str, Any],
    enrichment: dict[str, Any],
    analyst_comments: list[str] | None = None,
    source_system: str = "unknown",
) -> LLMScore:
    """
    Run the Claude ReAct agent and return an LLMScore.
    Called by fp_scorer.score_alert() as Layer 3.
    """
    verdict = await run_react_agent(
        alert_type=alert_type,
        severity=severity,
        source_system=source_system,
        raw_data=raw_data,
        analyst_comments=analyst_comments,
    )

    result = LLMScore.from_verdict(verdict)

    logger.info(
        "llm_score_complete",
        score=result.score,
        tool_steps=result.tool_steps,
        model=result.model_used,
        is_mock=result.model_used == "mock",
    )

    return result
