"""
Riley ReAct Agent — Claude-powered tool-use loop for false-positive analysis.

Claude reasons step-by-step, calling tools to gather evidence:
  1. check_ip_reputation  → threat intel score for an IP
  2. lookup_user          → corporate directory / AD lookup
  3. lookup_asset         → asset inventory lookup (known servers)
  4. check_time_context   → business-hours analysis
  5. submit_verdict       → final structured FP verdict (terminates the loop)

The agent loops until it calls submit_verdict or hits max_steps.
Falls back to a deterministic mock when ANTHROPIC_API_KEY is not set.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.core.logging import get_logger
from app.services.enrichment import mock_ad_lookup, mock_asset_lookup, mock_threat_intel

logger = get_logger(__name__)

# ── Tool definitions ──────────────────────────────────────────────────────────

_TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_ip_reputation",
        "description": (
            "Check threat intelligence for an IP address. "
            "Returns threat score (0–100), malicious classification, and categories. "
            "Use this for any src_ip, dest_ip, or remote IP in the alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"}
            },
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_user",
        "description": (
            "Look up a username in the corporate directory (Active Directory / Okta). "
            "Returns department, job title, and whether the account exists. "
            "Use this when the alert contains a username or user field."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username to look up (without domain prefix)"}
            },
            "required": ["username"],
        },
    },
    {
        "name": "lookup_asset",
        "description": (
            "Look up a hostname in the corporate asset inventory. "
            "Returns whether it's a known managed server and its criticality tier. "
            "Use this when the alert contains a hostname, host, or dest_host field."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Hostname to look up"}
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "check_time_context",
        "description": (
            "Check whether an alert timestamp falls within business hours (Mon–Fri 08:00–18:00 UTC). "
            "Off-hours activity is a stronger threat signal. Pass the ISO timestamp from the alert if available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "iso_timestamp": {
                    "type": "string",
                    "description": "ISO 8601 timestamp, e.g. 2026-07-04T03:14:00Z. Use current time if not in alert."
                }
            },
            "required": ["iso_timestamp"],
        },
    },
    {
        "name": "submit_verdict",
        "description": (
            "Submit your final false-positive verdict after gathering sufficient evidence. "
            "Call this when you have enough information to make a confident decision. "
            "This terminates your analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "fp_score": {
                    "type": "integer",
                    "description": (
                        "False positive confidence score from 0 to 100. "
                        "0 = definitely a real threat. 100 = definitely a false positive."
                    ),
                    "minimum": 0,
                    "maximum": 100,
                },
                "reasoning": {
                    "type": "string",
                    "description": "Concise explanation of your verdict (max 200 characters)",
                },
                "suggested_action": {
                    "type": "string",
                    "enum": ["auto_suppress", "low_priority_review", "escalate_immediately"],
                    "description": (
                        "auto_suppress: high confidence FP, no analyst needed. "
                        "low_priority_review: probably FP but needs human glance. "
                        "escalate_immediately: credible threat, analyst must act now."
                    ),
                },
                "key_evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "2–5 bullet points summarising the evidence that drove your decision",
                },
            },
            "required": ["fp_score", "reasoning", "suggested_action", "key_evidence"],
        },
    },
]

_SYSTEM_PROMPT = """\
You are Riley, a senior SOC analyst specialised in false positive reduction for enterprise security teams.

YOUR MISSION: Determine whether each incoming alert is a false positive (benign activity misclassified as a threat) or a true positive (a real threat requiring investigation).

METHODOLOGY:
1. Read the alert carefully — understand what happened, the source system, severity, and raw data fields.
2. Use your tools to gather evidence. Investigate IPs, users, and assets mentioned in the alert.
3. Reason about what the evidence means in context. A PowerShell command from IT Ops during business hours is very different from the same command from an unknown user at 3 AM.
4. Call submit_verdict with your final decision.

FALSE POSITIVE SCORE GUIDE (0–100):
• 90–100  Almost certainly FP  (e.g., known IT admin running a scheduled script during business hours on a managed server)
• 70–89   Likely FP            (indicators lean benign, minor ambiguity)
• 40–69   Ambiguous            (mixed signals — needs human review)
• 20–39   Likely TP            (suspicious indicators present)
• 0–19    Almost certainly TP  (known malicious IP, off-hours lateral movement, C2 beacon pattern, privilege escalation)

EFFICIENCY RULE: Use the minimum tools needed for a confident decision. Do not call a tool if the answer is already clear from the data you have.
"""


# ── Tool executor ─────────────────────────────────────────────────────────────

async def _run_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a tool call and return JSON string result."""
    try:
        if name == "check_ip_reputation":
            result = await mock_threat_intel(args["ip"])
            return json.dumps(result)

        elif name == "lookup_user":
            result = await mock_ad_lookup(args["username"])
            return json.dumps(result)

        elif name == "lookup_asset":
            result = await mock_asset_lookup(args["hostname"])
            return json.dumps(result)

        elif name == "check_time_context":
            try:
                ts = datetime.fromisoformat(args["iso_timestamp"].replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
            is_biz = 8 <= ts.hour < 18 and ts.weekday() < 5
            return json.dumps({
                "timestamp": ts.isoformat(),
                "is_business_hours": is_biz,
                "day_of_week": ts.strftime("%A"),
                "hour_utc": ts.hour,
                "note": "Business hours = Mon–Fri 08:00–18:00 UTC",
            })

        elif name == "submit_verdict":
            # Acknowledged — the main loop extracts the verdict from input
            return json.dumps({"status": "verdict_recorded"})

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

    except Exception as exc:
        logger.warning("react_tool_error", tool=name, error=str(exc))
        return json.dumps({"error": str(exc)})


# ── Verdict dataclass ─────────────────────────────────────────────────────────

class ReActVerdict:
    """Structured output from the ReAct agent."""

    def __init__(
        self,
        score: float,
        reason: str,
        suggested_action: str,
        evidence: list[str],
        tool_steps: int,
        model_used: str,
    ) -> None:
        self.score = score
        self.reason = reason
        self.suggested_action = suggested_action  # raw Claude value
        self.evidence = evidence
        self.tool_steps = tool_steps
        self.model_used = model_used

    @property
    def action_label(self) -> str:
        """Map Claude's enum to Riley's internal action string."""
        return {
            "auto_suppress": "Auto-suppress — confirmed false positive",
            "low_priority_review": "Queue for low-priority analyst review",
            "escalate_immediately": "Escalate to analyst — potential real threat",
        }.get(self.suggested_action, self.suggested_action)


# ── Main agent loop ───────────────────────────────────────────────────────────

async def run_react_agent(
    alert_type: str,
    severity: str,
    source_system: str,
    raw_data: dict[str, Any],
    analyst_comments: list[str] | None = None,
) -> ReActVerdict:
    """
    Run the Claude ReAct agent on a single alert.

    Returns a ReActVerdict. Falls back to deterministic mock if no API key.
    """
    if not settings.ANTHROPIC_API_KEY:
        logger.info("react_agent_mock", reason="no_ANTHROPIC_API_KEY")
        return _mock_verdict(alert_type, raw_data)

    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    except ImportError:
        logger.warning("react_agent_mock", reason="anthropic_not_installed")
        return _mock_verdict(alert_type, raw_data)

    # Build the initial user message
    comments_block = (
        f"\n**Analyst Notes:** {'; '.join(analyst_comments)}"
        if analyst_comments
        else ""
    )
    user_message = (
        f"Analyze this security alert and determine if it is a false positive:\n\n"
        f"**Alert Type:** {alert_type}\n"
        f"**Severity:** {severity}\n"
        f"**Source System:** {source_system}\n"
        f"**Raw Alert Data:**\n```json\n{json.dumps(raw_data, indent=2, default=str)}\n```"
        f"{comments_block}\n\n"
        f"Investigate the evidence and submit your verdict."
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    verdict: ReActVerdict | None = None
    tool_steps = 0
    max_steps = 10  # safety cap

    try:
        while tool_steps < max_steps:
            response = await client.messages.create(
                model=settings.ANTHROPIC_MODEL,
                max_tokens=1024,
                system=_SYSTEM_PROMPT,
                tools=_TOOLS,
                messages=messages,
            )

            logger.info(
                "react_agent_turn",
                stop_reason=response.stop_reason,
                tool_steps=tool_steps,
            )

            # Append assistant turn to conversation
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                # Claude finished without submitting verdict — shouldn't happen, but handle it
                logger.warning("react_agent_no_tool_call", stop_reason="end_turn")
                break

            if response.stop_reason != "tool_use":
                break

            # Process all tool calls in this turn
            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_steps += 1
                logger.info("react_tool_call", tool=block.name, args=block.input)

                if block.name == "submit_verdict":
                    # Extract the final verdict
                    inp = block.input
                    verdict = ReActVerdict(
                        score=float(inp.get("fp_score", 50)),
                        reason=str(inp.get("reasoning", ""))[:200],
                        suggested_action=str(inp.get("suggested_action", "low_priority_review")),
                        evidence=list(inp.get("key_evidence", [])),
                        tool_steps=tool_steps,
                        model_used=settings.ANTHROPIC_MODEL,
                    )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps({"status": "verdict_recorded"}),
                    })
                else:
                    result_str = await _run_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

            if verdict is not None:
                break  # done

    except Exception as exc:
        logger.warning("react_agent_exception", error=str(exc))
        return _mock_verdict(alert_type, raw_data)

    if verdict is None:
        logger.warning("react_agent_no_verdict", tool_steps=tool_steps)
        return _mock_verdict(alert_type, raw_data)

    logger.info(
        "react_agent_done",
        score=verdict.score,
        action=verdict.suggested_action,
        tool_steps=verdict.tool_steps,
        model=verdict.model_used,
    )
    return verdict


# ── Deterministic fallback ────────────────────────────────────────────────────

def _mock_verdict(alert_type: str, raw_data: dict[str, Any]) -> ReActVerdict:
    """
    Used when no ANTHROPIC_API_KEY is set or the SDK isn't installed.
    Produces a score based on simple heuristics so the system still works.
    """
    score = 45.0
    evidence: list[str] = ["[MOCK] No ANTHROPIC_API_KEY — using deterministic fallback"]

    alert_lower = alert_type.lower()
    if any(kw in alert_lower for kw in ("scan", "compliance_check", "backup")):
        score = 68.0
        evidence = ["[MOCK] Alert type matches known benign scanning/backup patterns"]
    elif any(kw in alert_lower for kw in ("lateral", "c2", "beacon", "exfil")):
        score = 18.0
        evidence = ["[MOCK] Alert type matches high-risk attack technique pattern"]

    return ReActVerdict(
        score=score,
        reason="[MOCK] No ANTHROPIC_API_KEY configured — deterministic fallback scoring",
        suggested_action="low_priority_review",
        evidence=evidence,
        tool_steps=0,
        model_used="mock",
    )
