"""
LangChain-based tactical agent orchestrator.

Each tactical agent (Network Recon, Vuln Scanner, Config Audit) is wrapped as a
LangChain StructuredTool. A deterministic LCEL pipeline runs them in the correct
order for a given asset:

    scope_check → network_recon → vuln_scanner → [config_audit if aws_account]

Each tool is:
  - Retried up to 2 times on transient errors (network timeout, etc.)
  - Scoped to verified assets only -- PermissionError propagates as a clean skip
  - Logged to the AgentRun audit table via the existing runner helpers

This module is the foundation for a future LLM-driven orchestrator that can
decide WHICH agents to run and in WHAT ORDER based on asset type, prior findings,
and threat context -- swap the deterministic pipeline for a LangChain ReAct agent
or LangGraph graph when ready (Phase 2).

Public API (mirrors runner.py so main.py needs zero changes):
    run_scan_pipeline(asset, db) -> list[AgentRun]
"""

import json
import logging
from datetime import datetime
from typing import Optional

from langchain_core.tools import StructuredTool
from langchain_core.runnables import RunnableSequence, RunnableLambda
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import models
from app.agents import network_recon, vuln_scanner, config_audit, triage

logger = logging.getLogger("longclaw.orchestrator")

AGENT_SOURCE = {
    "network-recon": "NETWORK_RECON",
    "vuln-scanner": "VULN_SCANNER",
    "config-audit": "CONFIG_AUDIT",
}


# ---------------------------------------------------------------------------
# Shared helpers (same as runner.py -- orchestrator owns the logic now)
# ---------------------------------------------------------------------------

def _record_run(
    db: Session,
    agent: str,
    asset: models.Asset,
    status: str,
    summary: Optional[str],
    alert_id: Optional[str] = None,
) -> models.AgentRun:
    run = models.AgentRun(
        agent=agent,
        asset_id=asset.id if asset else None,
        asset_target=asset.target if asset else None,
        status=status,
        summary=summary,
        alert_id=alert_id,
        finished_at=datetime.utcnow(),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _raise_alert(db: Session, source: str, description: str) -> models.Alert:
    alert = models.Alert(source=source, description=description)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    result = triage.classify(alert.description, alert.source)
    triage.apply_classification(alert, result)
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Tool input schemas (Pydantic -- required by StructuredTool)
# ---------------------------------------------------------------------------

class ScanContext(BaseModel):
    """Shared context passed through the pipeline."""
    asset_id: str = Field(description="Asset primary key")
    open_ports: Optional[list[int]] = Field(
        default=None,
        description="Open ports from a prior Network Recon run, if available.",
    )
    runs: list[str] = Field(
        default_factory=list,
        description="Accumulated AgentRun IDs from earlier steps.",
    )


# ---------------------------------------------------------------------------
# LangChain StructuredTools
# Each tool accepts a ScanContext + the live db session via closure.
# ---------------------------------------------------------------------------

def _make_network_recon_tool(db: Session, asset: models.Asset) -> StructuredTool:
    def _run(asset_id: str, open_ports=None, runs=None) -> dict:
        if asset.status != "verified":
            ar = _record_run(db, "network-recon", asset, "skipped_unverified",
                             f"Skipped '{asset.target}' -- not verified.")
            return {"asset_id": asset_id, "open_ports": None, "runs": [ar.id]}
        try:
            finding = network_recon.run(asset)
        except PermissionError as e:
            ar = _record_run(db, "network-recon", asset, "skipped_unverified", str(e))
            return {"asset_id": asset_id, "open_ports": None, "runs": [ar.id]}

        asset.last_scanned_at = datetime.utcnow()
        alert_id = None
        discovered_ports = None
        if finding:
            if finding.get("open_ports") is not None and finding.get("resolved_ip"):
                asset.scan_baseline = json.dumps(finding["open_ports"])
                discovered_ports = finding["open_ports"]
            alert = _raise_alert(db, AGENT_SOURCE["network-recon"], finding["summary"])
            alert_id = alert.id
        db.commit()
        ar = _record_run(db, "network-recon", asset, "ok",
                         finding["summary"] if finding else "No changes from baseline.",
                         alert_id)
        logger.info("network-recon completed for %s: %s", asset.target, ar.status)
        return {"asset_id": asset_id, "open_ports": discovered_ports, "runs": [ar.id]}

    return StructuredTool.from_function(
        func=_run,
        name="network_recon",
        description="Run TCP port scan against the asset and diff against stored baseline.",
        args_schema=ScanContext,
    )


def _make_vuln_scanner_tool(db: Session, asset: models.Asset) -> StructuredTool:
    def _run(asset_id: str, open_ports=None, runs=None) -> dict:
        if asset.status != "verified":
            ar = _record_run(db, "vuln-scanner", asset, "skipped_unverified",
                             f"Skipped '{asset.target}' -- not verified.")
            return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}
        ports = open_ports or (json.loads(asset.scan_baseline) if asset.scan_baseline else
                               network_recon.scan_ports(asset.target))
        try:
            finding = vuln_scanner.run(asset, ports)
        except PermissionError as e:
            ar = _record_run(db, "vuln-scanner", asset, "skipped_unverified", str(e))
            return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}

        alert_id = None
        if finding:
            alert = _raise_alert(db, AGENT_SOURCE["vuln-scanner"], finding["summary"])
            alert_id = alert.id
        ar = _record_run(db, "vuln-scanner", asset, "ok",
                         finding["summary"] if finding else "No known-vulnerable banners matched.",
                         alert_id)
        logger.info("vuln-scanner completed for %s: %s", asset.target, ar.status)
        return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}

    return StructuredTool.from_function(
        func=_run,
        name="vuln_scanner",
        description="Banner-grab open ports and match against known CVE version ranges.",
        args_schema=ScanContext,
    )


def _make_config_audit_tool(db: Session, asset: models.Asset) -> StructuredTool:
    def _run(asset_id: str, open_ports=None, runs=None) -> dict:
        if asset.status != "verified":
            ar = _record_run(db, "config-audit", asset, "skipped_unverified",
                             f"Skipped '{asset.target}' -- not verified.")
            return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}
        try:
            finding = config_audit.run(asset)
        except PermissionError as e:
            ar = _record_run(db, "config-audit", asset, "skipped_unverified", str(e))
            return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}

        if finding is None:
            ar = _record_run(db, "config-audit", asset, "ok", "No drift detected / not applicable.")
            return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}

        alert_id = None
        if not finding.get("mock") and finding.get("findings"):
            alert = _raise_alert(db, AGENT_SOURCE["config-audit"], finding["summary"])
            alert_id = alert.id
        ar = _record_run(db, "config-audit", asset, "ok", finding["summary"], alert_id)
        logger.info("config-audit completed for %s: %s", asset.target, ar.status)
        return {"asset_id": asset_id, "open_ports": open_ports, "runs": (runs or []) + [ar.id]}

    return StructuredTool.from_function(
        func=_run,
        name="config_audit",
        description="Check AWS S3 and security group configurations for public exposure.",
        args_schema=ScanContext,
    )


# ---------------------------------------------------------------------------
# LCEL pipeline builder
# ---------------------------------------------------------------------------

def _build_pipeline(db: Session, asset: models.Asset) -> RunnableSequence:
    """
    Build a deterministic LCEL scan pipeline for this asset.

    Network Recon → Vuln Scanner → [Config Audit if aws_account]

    Each step receives the output dict of the previous step, so open_ports
    discovered by Network Recon flow into Vuln Scanner automatically.

    Future LLM-driven version: replace this with a LangGraph StateGraph where
    an Orchestrator LLM node decides which tool to invoke next based on findings.
    """
    recon_tool = _make_network_recon_tool(db, asset).with_retry(stop_after_attempt=2)
    vuln_tool = _make_vuln_scanner_tool(db, asset).with_retry(stop_after_attempt=2)

    steps = [
        RunnableLambda(lambda ctx: recon_tool.invoke(ctx)),
        RunnableLambda(lambda ctx: vuln_tool.invoke(ctx)),
    ]

    if asset.asset_type == "aws_account":
        audit_tool = _make_config_audit_tool(db, asset).with_retry(stop_after_attempt=2)
        steps.append(RunnableLambda(lambda ctx: audit_tool.invoke(ctx)))

    return RunnableSequence(*steps)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_scan_pipeline(db: Session, asset: models.Asset) -> list[models.AgentRun]:
    """
    Run the full tactical scan pipeline for an asset via LangChain LCEL.
    Returns all AgentRun records created during this pipeline execution.
    """
    initial_ctx = {
        "asset_id": asset.id,
        "open_ports": None,
        "runs": [],
    }
    pipeline = _build_pipeline(db, asset)
    try:
        final_ctx = pipeline.invoke(initial_ctx)
        run_ids = final_ctx.get("runs", [])
    except Exception as e:
        logger.exception("Pipeline failed for asset %s: %s", asset.target, e)
        run_ids = []

    if not run_ids:
        return []
    return db.query(models.AgentRun).filter(models.AgentRun.id.in_(run_ids)).all()
