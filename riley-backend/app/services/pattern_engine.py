"""
Pattern Engine — extract signatures from alerts and match against LearnedPatterns.
Signatures are normalized (IPs, domains, timestamps stripped) so the same alert
structure from different hosts maps to the same pattern.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.pattern import LearnedPattern

logger = get_logger(__name__)

# Regexes for normalising sensitive/variable data out of signatures
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def _normalise_value(value: str) -> str:
    v = _IP_RE.sub("<IP>", value)
    v = _DOMAIN_RE.sub("<DOMAIN>", v)
    v = _TIMESTAMP_RE.sub("<TIMESTAMP>", v)
    v = _UUID_RE.sub("<UUID>", v)
    v = _HEX_RE.sub("<HASH>", v)
    return v


def _normalise_dict(data: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "<DEEP>"
    if isinstance(data, dict):
        return {k: _normalise_dict(v, depth + 1) for k, v in sorted(data.items())}
    if isinstance(data, list):
        return [_normalise_dict(i, depth + 1) for i in data]
    if isinstance(data, str):
        return _normalise_value(data)
    return data


def extract_signature(alert_type: str, raw_data: dict[str, Any]) -> dict[str, Any]:
    """
    Produce a normalised, reproducible signature from an alert.
    The signature captures structural shape, not variable values.
    """
    normalised = _normalise_dict(raw_data)
    sig = {
        "alert_type": alert_type,
        "top_level_keys": sorted(raw_data.keys()),
        "normalised_payload": normalised,
    }
    # Stable hash for fast equality checks
    sig["sig_hash"] = hashlib.sha256(
        json.dumps(sig, sort_keys=True).encode()
    ).hexdigest()[:16]
    return sig


def _jaccard_similarity(sig_a: dict[str, Any], sig_b: dict[str, Any]) -> float:
    """Simple Jaccard on top-level key sets plus alert_type match bonus."""
    if sig_a.get("alert_type") != sig_b.get("alert_type"):
        return 0.0

    keys_a = set(sig_a.get("top_level_keys", []))
    keys_b = set(sig_b.get("top_level_keys", []))
    if not keys_a and not keys_b:
        return 1.0
    intersection = len(keys_a & keys_b)
    union = len(keys_a | keys_b)
    return intersection / union if union else 0.0


async def match_patterns(
    alert_type: str,
    signature: dict[str, Any],
    db: AsyncSession,
    top_k: int = 5,
) -> tuple[float, str]:
    """
    Find similar LearnedPatterns and return a weighted FP score contribution.
    Returns (score_delta: -30..+40, reason: str).
    """
    result = await db.execute(
        select(LearnedPattern)
        .where(LearnedPattern.alert_type == alert_type)
        .order_by(LearnedPattern.occurrences.desc())
        .limit(50)
    )
    patterns: list[LearnedPattern] = list(result.scalars().all())

    if not patterns:
        return 0.0, "no_learned_patterns"

    best_sim = 0.0
    best_pattern: LearnedPattern | None = None

    for p in patterns:
        sim = _jaccard_similarity(signature, p.pattern_signature)
        if sim > best_sim:
            best_sim = sim
            best_pattern = p

    if best_pattern is None or best_sim < 0.3:
        return 0.0, "no_matching_pattern"

    # Scale contribution by similarity × pattern confidence
    raw_delta = best_sim * (best_pattern.pattern_confidence * 2 - 1) * 40
    # pattern_confidence 0.5 → 0 delta; 1.0 → +40 delta; 0.0 → -40 delta
    reason = (
        f"pattern_match(sim={best_sim:.2f}, conf={best_pattern.pattern_confidence:.2f}, "
        f"n={best_pattern.occurrences})"
    )
    logger.info("pattern_match", alert_type=alert_type, similarity=best_sim,
                confidence=best_pattern.pattern_confidence)
    return raw_delta, reason


async def upsert_pattern(
    alert_type: str,
    signature: dict[str, Any],
    verdict: str,  # "fp" | "true_positive"
    db: AsyncSession,
) -> LearnedPattern:
    """
    Create or update a LearnedPattern from analyst feedback.
    Recalculates confidence after each update.
    """
    sig_hash = signature.get("sig_hash", "")

    # Try to find an existing pattern with the same hash
    result = await db.execute(
        select(LearnedPattern)
        .where(
            LearnedPattern.alert_type == alert_type,
        )
    )
    all_patterns = list(result.scalars().all())

    existing: LearnedPattern | None = None
    for p in all_patterns:
        if p.pattern_signature.get("sig_hash") == sig_hash:
            existing = p
            break

    if existing:
        existing.occurrences += 1
        if verdict == "fp":
            existing.fp_count += 1
        else:
            existing.tp_count += 1
        total = existing.fp_count + existing.tp_count
        existing.pattern_confidence = existing.fp_count / total if total else 0.5
        logger.info("pattern_updated", id=existing.id, confidence=existing.pattern_confidence)
        return existing
    else:
        fp_c = 1 if verdict == "fp" else 0
        tp_c = 1 if verdict == "true_positive" else 0
        new_pattern = LearnedPattern(
            alert_type=alert_type,
            pattern_signature=signature,
            pattern_confidence=fp_c / (fp_c + tp_c),
            occurrences=1,
            fp_count=fp_c,
            tp_count=tp_c,
        )
        db.add(new_pattern)
        await db.flush()
        logger.info("pattern_created", alert_type=alert_type, id=new_pattern.id)
        return new_pattern
