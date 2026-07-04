"""
Webhook Service — Slack / Discord notifications.
Sends daily digest and per-alert auto-suppress notifications.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


async def _post_webhook(url: str, payload: dict[str, Any]) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.warning("webhook_failed", url=url[:40], error=str(exc))
        return False


def _slack_payload(text: str, blocks: list[dict] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    return payload


def _discord_payload(content: str, embeds: list[dict] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"content": content}
    if embeds:
        payload["embeds"] = embeds
    return payload


async def notify_auto_suppressed(alert_id: int, alert_type: str, score: float) -> None:
    """Fire-and-forget notification when an alert is auto-suppressed."""
    msg = (
        f"🛡️ *Riley Auto-Suppressed Alert*\n"
        f"Alert #{alert_id} | Type: `{alert_type}` | FP Confidence: *{score:.0f}%*\n"
        f"_No analyst action required._"
    )
    tasks = []
    if settings.SLACK_WEBHOOK_URL:
        tasks.append(_post_webhook(settings.SLACK_WEBHOOK_URL, _slack_payload(msg)))
    if settings.DISCORD_WEBHOOK_URL:
        tasks.append(_post_webhook(
            settings.DISCORD_WEBHOOK_URL,
            _discord_payload(msg.replace("*", "**").replace("`", "`")),
        ))
    if tasks:
        await asyncio.gather(*tasks)


async def send_daily_digest(stats: dict[str, Any]) -> None:
    """
    Send end-of-day summary to Slack and/or Discord.
    stats keys: alerts_processed, fps_blocked, hours_saved, accuracy_rate
    """
    processed = stats.get("alerts_processed", 0)
    blocked = stats.get("fps_blocked", 0)
    hours = stats.get("hours_saved", 0.0)
    accuracy = stats.get("accuracy_rate", 0.0)

    # Slack (rich block format)
    slack_blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🤖 Riley Daily Digest"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Alerts Processed*\n{processed}"},
                {"type": "mrkdwn", "text": f"*FPs Blocked*\n{blocked}"},
                {"type": "mrkdwn", "text": f"*Hours Saved*\n{hours:.1f} hrs"},
                {"type": "mrkdwn", "text": f"*Accuracy Rate*\n{accuracy:.1f}%"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "_Riley — AI False Positive Slayer | 🔪 Cutting noise since 2024_",
                }
            ],
        },
    ]
    slack_msg = f"Riley Daily: {blocked}/{processed} FPs blocked, {hours:.1f}h saved, {accuracy:.0f}% accuracy"

    # Discord embed
    discord_embed = {
        "title": "🤖 Riley Daily Digest",
        "color": 0x4D8FFF,
        "fields": [
            {"name": "Alerts Processed", "value": str(processed), "inline": True},
            {"name": "FPs Blocked", "value": str(blocked), "inline": True},
            {"name": "Hours Saved", "value": f"{hours:.1f} hrs", "inline": True},
            {"name": "Accuracy Rate", "value": f"{accuracy:.1f}%", "inline": True},
        ],
        "footer": {"text": "Riley — AI False Positive Slayer"},
    }

    tasks = []
    if settings.SLACK_WEBHOOK_URL:
        tasks.append(_post_webhook(
            settings.SLACK_WEBHOOK_URL,
            _slack_payload(slack_msg, slack_blocks),
        ))
    if settings.DISCORD_WEBHOOK_URL:
        tasks.append(_post_webhook(
            settings.DISCORD_WEBHOOK_URL,
            _discord_payload("📊 Riley Daily Report", [discord_embed]),
        ))

    if tasks:
        results = await asyncio.gather(*tasks)
        logger.info("daily_digest_sent", destinations=len(tasks), successes=sum(results))
    else:
        logger.info("daily_digest_skipped", reason="no_webhooks_configured")
