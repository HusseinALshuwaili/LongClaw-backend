"""
LLM Service — OpenAI gpt-4o-mini for FP enrichment.
Falls back to deterministic mock when no API key is configured.
"""
from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class LLMScore:
    def __init__(self, score: float, reason: str, suggested_action: str) -> None:
        self.score = score
        self.reason = reason
        self.suggested_action = suggested_action


_SYSTEM_PROMPT = """You are Riley, a senior security analyst specialising in false positive reduction.
Given alert details and enrichment context, rate the likelihood this is a false positive from 0 to 100.
0 = definitely a real threat. 100 = definitely a false positive.
Return ONLY valid JSON with keys: score (int), reason (string, max 120 chars), suggested_action (string).
"""


async def score_with_llm(
    alert_type: str,
    severity: str,
    raw_data: dict[str, Any],
    enrichment: dict[str, Any],
    analyst_comments: list[str] | None = None,
) -> LLMScore:
    """Call OpenAI for FP likelihood score. Falls back to mock on error or no key."""

    if not settings.OPENAI_API_KEY:
        logger.info("llm_mock_mode", reason="no_api_key")
        return _mock_score(alert_type, enrichment)

    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        user_content = json.dumps({
            "alert_type": alert_type,
            "severity": severity,
            "raw_data": raw_data,
            "enrichment": enrichment,
            "analyst_comments": analyst_comments or [],
        }, default=str)

        response = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            response_format={"type": "json_object"},
            max_tokens=256,
            temperature=0.1,
        )

        content = response.choices[0].message.content or "{}"
        parsed = json.loads(content)

        return LLMScore(
            score=float(parsed.get("score", 50)),
            reason=str(parsed.get("reason", "LLM analysis")),
            suggested_action=str(parsed.get("suggested_action", "Review manually")),
        )

    except Exception as exc:
        logger.warning("llm_call_failed", error=str(exc))
        return _mock_score(alert_type, enrichment)


def _mock_score(alert_type: str, enrichment: dict[str, Any]) -> LLMScore:
    """
    Deterministic mock — used when OpenAI is unavailable.
    Bases score on enrichment signals so tests are predictable.
    """
    score = 45.0  # neutral baseline
    reasons = []

    dept = enrichment.get("user_department", "")
    if dept in ("IT Operations", "DevOps"):
        score += 22
        reasons.append("ops team user")

    if enrichment.get("asset_is_known_server"):
        score += 12
        reasons.append("known managed asset")

    ti = enrichment.get("threat_intel_score", 0)
    if ti >= 70:
        score -= 35
        reasons.append(f"threat intel score {ti}")
    elif ti >= 40:
        score -= 10
        reasons.append(f"moderate threat intel {ti}")

    ps_types = {"powershell_execution", "script_block_logging", "encoded_command"}
    if any(t in alert_type.lower() for t in ps_types) and dept == "IT Operations":
        score += 15
        reasons.append("IT running PowerShell")

    score = max(0.0, min(100.0, score))
    reason_str = ", ".join(reasons) if reasons else "pattern analysis"
    action = (
        "Auto-suppress" if score >= 85
        else "Queue for review" if score >= 60
        else "Escalate to analyst"
    )

    return LLMScore(score=score, reason=f"[MOCK] {reason_str}", suggested_action=action)
