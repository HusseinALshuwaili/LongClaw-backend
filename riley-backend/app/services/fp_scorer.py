"""
False Positive Scoring Engine — Riley's core brain.

Three-layer hybrid approach:
  1. Rule-based  (fast, deterministic, no LLM cost)
  2. Pattern matching  (LearnedPatterns table — gets smarter with every verdict)
  3. LLM enrichment  (OpenAI gpt-4o-mini — only when score is ambiguous)

Outputs:
  fp_confidence_score: 0–100  (100 = definitely FP)
  action: "AUTO_SUPPRESS" | "LOW_PRIORITY_REVIEW" | "ESCALATE"
  reason: human-readable explanation string
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.logging import get_logger
from app.services import llm_service
from app.services.pattern_engine import match_patterns

logger = get_logger(__name__)


# ── Rule definitions ─────────────────────────────────────────────────────────

def _is_business_hours(dt: datetime | None) -> bool:
    if dt is None:
        return True
    local = dt.astimezone(timezone.utc)
    return 8 <= local.hour < 18 and local.weekday() < 5  # Mon–Fri, 08-18 UTC


_RULES: list[dict[str, Any]] = [
    # 1. IT Ops running PowerShell during business hours → strong FP indicator
    {
        "name": "itops_powershell_biz_hours",
        "condition": lambda d, e, dt: (
            e.get("user_department") in ("IT Operations", "DevOps")
            and any(kw in d.get("alert_type", "").lower()
                    for kw in ("powershell", "script_block", "encoded_command"))
            and _is_business_hours(dt)
        ),
        "delta": +40.0,
        "reason": "IT Ops PowerShell during business hours",
    },
    # 2. Known managed server + low/info severity
    {
        "name": "known_server_low_sev",
        "condition": lambda d, e, dt: (
            e.get("asset_is_known_server") is True
            and d.get("severity", "medium") in ("low", "info")
        ),
        "delta": +25.0,
        "reason": "Known managed server, low severity",
    },
    # 3. Scheduled task from ops team
    {
        "name": "scheduled_task_ops",
        "condition": lambda d, e, dt: (
            "scheduled_task" in d.get("alert_type", "").lower()
            and e.get("user_department") in ("IT Operations", "DevOps")
        ),
        "delta": +35.0,
        "reason": "Scheduled task from operations team",
    },
    # 4. High threat intel score → likely TP
    {
        "name": "threat_intel_high",
        "condition": lambda d, e, dt: e.get("threat_intel_score", 0) >= 70,
        "delta": -40.0,
        "reason": "High threat intelligence score — likely malicious",
    },
    # 5. Moderate threat intel
    {
        "name": "threat_intel_moderate",
        "condition": lambda d, e, dt: 40 <= e.get("threat_intel_score", 0) < 70,
        "delta": -15.0,
        "reason": "Moderate threat intelligence score",
    },
    # 6. Critical severity outside business hours
    {
        "name": "critical_after_hours",
        "condition": lambda d, e, dt: (
            d.get("severity") == "critical"
            and not _is_business_hours(dt)
        ),
        "delta": -30.0,
        "reason": "Critical alert outside business hours",
    },
    # 7. Unknown user (not in AD)
    {
        "name": "unknown_user",
        "condition": lambda d, e, dt: (
            d.get("raw_data", {}).get("username") is not None
            and e.get("user_department") is None
        ),
        "delta": -10.0,
        "reason": "User not found in directory — unmanaged account",
    },
    # 8. Scanner/security tooling pattern (often FP)
    {
        "name": "scanner_pattern",
        "condition": lambda d, e, dt: any(
            kw in d.get("alert_type", "").lower()
            for kw in ("nmap", "vulnerability_scan", "port_scan", "compliance_check")
        ),
        "delta": +20.0,
        "reason": "Matches security scanner / compliance tool pattern",
    },
    # 9. Backup job pattern
    {
        "name": "backup_job",
        "condition": lambda d, e, dt: any(
            kw in str(d.get("raw_data", {})).lower()
            for kw in ("backup", "veeam", "commvault", "tsm")
        ),
        "delta": +30.0,
        "reason": "Backup job activity pattern",
    },
]


def _apply_rules(
    raw_data: dict[str, Any],
    enrichment: dict[str, Any],
    alert_type: str,
    severity: str,
    created_at: datetime | None,
) -> tuple[float, list[str]]:
    """Apply all rules. Returns (total_delta, list_of_triggered_reasons)."""
    # Merge alert fields into a single lookup dict for lambda
    lookup = {**raw_data, "alert_type": alert_type, "severity": severity}
    total_delta = 0.0
    fired_reasons: list[str] = []

    for rule in _RULES:
        try:
            if rule["condition"](lookup, enrichment, created_at):
                total_delta += rule["delta"]
                fired_reasons.append(rule["reason"])
                logger.debug("rule_fired", rule=rule["name"], delta=rule["delta"])
        except Exception as exc:
            logger.warning("rule_error", rule=rule["name"], error=str(exc))

    return total_delta, fired_reasons


# ── Public API ────────────────────────────────────────────────────────────────

class ScoringResult:
    def __init__(
        self,
        fp_confidence: float,
        action: str,
        reason: str,
        suggested_action: str,
    ) -> None:
        self.fp_confidence = fp_confidence
        self.action = action            # AUTO_SUPPRESS | LOW_PRIORITY_REVIEW | ESCALATE
        self.reason = reason
        self.suggested_action = suggested_action


async def score_alert(
    alert_type: str,
    severity: str,
    raw_data: dict[str, Any],
    enrichment: dict[str, Any],
    signature: dict[str, Any],
    created_at: datetime | None,
    analyst_comments: list[str] | None,
    db: AsyncSession,
) -> ScoringResult:
    """
    Main entry point. Runs all three scoring layers and returns a ScoringResult.
    """
    # ── Layer 1: Rules ────────────────────────────────────────
    rule_delta, rule_reasons = _apply_rules(
        raw_data, enrichment, alert_type, severity, created_at
    )

    # ── Layer 2: Pattern matching ─────────────────────────────
    pattern_delta, pattern_reason = await match_patterns(alert_type, signature, db)

    # Composite before LLM
    pre_llm_score = 50.0 + rule_delta + pattern_delta
    pre_llm_score = max(0.0, min(100.0, pre_llm_score))

    logger.info(
        "fp_score_pre_llm",
        alert_type=alert_type,
        rule_delta=rule_delta,
        pattern_delta=pattern_delta,
        pre_llm=pre_llm_score,
    )

    # ── Layer 3: LLM (only when ambiguous — saves tokens) ────
    llm_result = await llm_service.score_with_llm(
        alert_type=alert_type,
        severity=severity,
        raw_data=raw_data,
        enrichment=enrichment,
        analyst_comments=analyst_comments,
    )

    # Blend: 60% rule+pattern, 40% LLM
    final_score = pre_llm_score * 0.60 + llm_result.score * 0.40
    final_score = max(0.0, min(100.0, final_score))

    # Compile reason string
    all_reasons: list[str] = rule_reasons
    if pattern_reason not in ("no_learned_patterns", "no_matching_pattern"):
        all_reasons.append(pattern_reason)
    all_reasons.append(f"LLM({llm_result.score:.0f}): {llm_result.reason}")
    reason_str = " | ".join(all_reasons) if all_reasons else "no_signals"

    # ── Threshold logic → action ─────────────────────────────
    high_thresh = settings.FP_AUTO_SUPPRESS_THRESHOLD
    low_thresh = settings.FP_LOW_PRIORITY_THRESHOLD

    if final_score >= high_thresh:
        action = "AUTO_SUPPRESS"
        suggested = "Alert auto-suppressed as false positive. No analyst action required."
    elif final_score >= low_thresh:
        action = "LOW_PRIORITY_REVIEW"
        suggested = "Tagged for end-of-day review. Low priority."
    else:
        action = "ESCALATE"
        suggested = llm_result.suggested_action or "Escalate to analyst immediately."

    logger.info(
        "fp_score_final",
        alert_type=alert_type,
        final_score=final_score,
        action=action,
    )

    return ScoringResult(
        fp_confidence=round(final_score, 2),
        action=action,
        reason=reason_str,
        suggested_action=suggested,
    )
