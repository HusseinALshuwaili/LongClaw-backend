"""
Tactical agent runner — public API shim.

main.py calls these functions directly (run_network_recon, run_vuln_scanner,
run_config_audit, run_all_for_asset, run_sweep). This module keeps that
interface stable while delegating all real logic to orchestrator.py, which
owns the LangChain Tool wrappers, LCEL pipeline, retry logic, and audit logging.

To swap in the LLM-driven orchestrator in the future, change orchestrator.py
only — this shim stays the same.
"""
from sqlalchemy.orm import Session

from app import models
from app.agents import orchestrator
from app.agents.orchestrator import (
    _record_run,
    _raise_alert,
    AGENT_SOURCE,
)
from app.agents import network_recon, vuln_scanner, config_audit
import json
from datetime import datetime


# ---------------------------------------------------------------------------
# Single-agent run-now endpoints (called by main.py's manual-trigger routes)
# These run ONE agent at a time -- used when the operator clicks "Run now"
# on a specific agent from the dashboard.
# ---------------------------------------------------------------------------

def run_network_recon(db: Session, asset: models.Asset) -> models.AgentRun:
    if asset.status != "verified":
        return _record_run(db, "network-recon", asset, "skipped_unverified",
                           f"Skipped '{asset.target}' -- not verified.")
    try:
        finding = network_recon.run(asset)
    except PermissionError as e:
        return _record_run(db, "network-recon", asset, "skipped_unverified", str(e))

    asset.last_scanned_at = datetime.utcnow()
    alert_id = None
    if finding:
        if finding.get("open_ports") is not None and finding.get("resolved_ip"):
            asset.scan_baseline = json.dumps(finding["open_ports"])
        alert = _raise_alert(db, AGENT_SOURCE["network-recon"], finding["summary"])
        alert_id = alert.id
    db.commit()
    return _record_run(db, "network-recon", asset, "ok",
                       finding["summary"] if finding else "No changes from baseline.", alert_id)


def run_vuln_scanner(db: Session, asset: models.Asset) -> models.AgentRun:
    if asset.status != "verified":
        return _record_run(db, "vuln-scanner", asset, "skipped_unverified",
                           f"Skipped '{asset.target}' -- not verified.")
    open_ports = json.loads(asset.scan_baseline) if asset.scan_baseline else network_recon.scan_ports(asset.target)
    try:
        finding = vuln_scanner.run(asset, open_ports)
    except PermissionError as e:
        return _record_run(db, "vuln-scanner", asset, "skipped_unverified", str(e))

    alert_id = None
    if finding:
        alert = _raise_alert(db, AGENT_SOURCE["vuln-scanner"], finding["summary"])
        alert_id = alert.id
    return _record_run(db, "vuln-scanner", asset, "ok",
                       finding["summary"] if finding else "No known-vulnerable banners matched.", alert_id)


def run_config_audit(db: Session, asset: models.Asset) -> models.AgentRun:
    if asset.status != "verified":
        return _record_run(db, "config-audit", asset, "skipped_unverified",
                           f"Skipped '{asset.target}' -- not verified.")
    try:
        finding = config_audit.run(asset)
    except PermissionError as e:
        return _record_run(db, "config-audit", asset, "skipped_unverified", str(e))

    if finding is None:
        return _record_run(db, "config-audit", asset, "ok", "No drift detected / not applicable.")

    alert_id = None
    if not finding.get("mock") and finding.get("findings"):
        alert = _raise_alert(db, AGENT_SOURCE["config-audit"], finding["summary"])
        alert_id = alert.id
    return _record_run(db, "config-audit", asset, "ok", finding["summary"], alert_id)


# ---------------------------------------------------------------------------
# Full pipeline -- used by run-all endpoint and the scheduled sweep
# Delegates to the LangChain LCEL orchestrator.
# ---------------------------------------------------------------------------

def run_all_for_asset(db: Session, asset: models.Asset) -> list[models.AgentRun]:
    """Run all applicable agents via the LangChain orchestration pipeline."""
    return orchestrator.run_scan_pipeline(db, asset)


def run_sweep(db: Session) -> list[models.AgentRun]:
    """Scheduled sweep: run the full pipeline against every verified asset."""
    assets = db.query(models.Asset).filter(models.Asset.status == "verified").all()
    runs = []
    for asset in assets:
        runs.extend(run_all_for_asset(db, asset))
    return runs
