import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import ALLOWED_ORIGINS, SCAN_INTERVAL_MINUTES, ENABLE_SCHEDULER
from app.database import Base, engine, get_db, SessionLocal
from app import models, schemas
from app.agents import triage, runner
from app import verification

logger = logging.getLogger("longclaw.scheduler")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="LONGCLAW API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Scheduler -- this is the "real-time function" part of the MVP: every
# verified asset gets swept by the tactical agents on a timer, with no human
# needing to click anything. 10 minutes is a sane default for an MVP; this
# is the one knob to turn if scan cadence needs to change.
# ---------------------------------------------------------------------------
scheduler = BackgroundScheduler()


def _scheduled_sweep():
    db = SessionLocal()
    try:
        runs = runner.run_sweep(db)
        logger.info("Scheduled tactical sweep complete: %d agent run(s).", len(runs))
    except Exception:
        logger.exception("Scheduled tactical sweep failed.")
    finally:
        db.close()


@app.on_event("startup")
def start_scheduler():
    if not ENABLE_SCHEDULER:
        logger.info("ENABLE_SCHEDULER=false -- skipping sweep registration on this process.")
        return
    scheduler.add_job(_scheduled_sweep, "interval", minutes=SCAN_INTERVAL_MINUTES, id="tactical_sweep", replace_existing=True)
    scheduler.start()


@app.on_event("shutdown")
def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Alerts / Triage
# ---------------------------------------------------------------------------

@app.post("/ingest", response_model=schemas.AlertOut)
def ingest_alert(payload: schemas.AlertIngest, db: Session = Depends(get_db)):
    """Entry point for source tools (EDR, SIEM, email security, etc.) to push
    a raw event in. Runs the Triage Agent synchronously for now -- swap for
    an SQS-backed worker once volume justifies it (see roadmap Phase 1)."""
    alert = models.Alert(
        source=payload.source,
        description=payload.description,
        raw_payload=str(payload.raw_payload) if payload.raw_payload else None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    result = triage.classify(alert.description, alert.source)
    triage.apply_classification(alert, result)
    db.commit()
    db.refresh(alert)
    return alert


@app.get("/alerts", response_model=list[schemas.AlertOut])
def list_alerts(status: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Alert)
    if status:
        q = q.filter(models.Alert.status == status)
    return q.order_by(models.Alert.created_at.desc()).all()


@app.get("/alerts/kpis", response_model=schemas.KPIOut)
def alert_kpis(db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=24)
    ingested_24h = db.query(func.count(models.Alert.id)).filter(
        models.Alert.created_at >= since
    ).scalar() or 0
    sent_to_queue = db.query(func.count(models.Alert.id)).filter(
        models.Alert.status == "classified"
    ).scalar() or 0
    awaiting_review = db.query(func.count(models.Alert.id)).filter(
        models.Alert.status == "classified",
        models.Alert.resolution.is_(None),
    ).scalar() or 0
    dismissed_by_rules = db.query(func.count(models.Alert.id)).filter(
        models.Alert.rationale.like("Matched known-benign rule pattern%")
    ).scalar() or 0
    noise_reduced_pct = round((dismissed_by_rules / ingested_24h) * 100, 1) if ingested_24h else 0.0
    return schemas.KPIOut(
        ingested_24h=ingested_24h,
        sent_to_queue=sent_to_queue,
        awaiting_review=awaiting_review,
        noise_reduced_pct=noise_reduced_pct,
    )


@app.post("/alerts/{alert_id}/confirm", response_model=schemas.AlertOut)
def confirm_alert(alert_id: str, body: schemas.ResolveRequest, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.resolution = "escalated"
    alert.status = "escalated"
    alert.resolved_by = body.resolved_by
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


@app.post("/alerts/{alert_id}/dismiss", response_model=schemas.AlertOut)
def dismiss_alert(alert_id: str, body: schemas.ResolveRequest, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.resolution = "dismissed"
    alert.status = "dismissed"
    alert.resolved_by = body.resolved_by
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Asset registry
# ---------------------------------------------------------------------------

@app.post("/assets", response_model=schemas.AssetOut)
def register_asset(payload: schemas.AssetRegister, db: Session = Depends(get_db)):
    asset = models.Asset(
        target=payload.target,
        asset_type=payload.asset_type,
        owner_email=payload.owner_email,
        verification_method=payload.verification_method,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@app.get("/assets", response_model=list[schemas.AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(models.Asset).order_by(models.Asset.created_at.desc()).all()


@app.post("/assets/{asset_id}/verify", response_model=schemas.AssetOut)
def verify_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")

    if asset.verification_method == "dns_txt":
        ok, detail = verification.verify_dns_txt(asset.target, asset.verification_token)
    else:
        ok, detail = verification.verify_iam_role(asset.target, asset.verification_token)

    asset.status = "verified" if ok else "failed"
    if ok:
        asset.verified_at = datetime.utcnow()
    db.commit()
    db.refresh(asset)
    if not ok:
        raise HTTPException(400, detail)
    return asset


# ---------------------------------------------------------------------------
# Tactical agents -- manual run-now + audit trail
#
# The scheduler above covers "real-time / continuous" coverage automatically.
# These endpoints exist so the dashboard can offer an explicit "Scan now"
# action per asset, and so the agent-health panel has something real to read
# instead of static numbers.
# ---------------------------------------------------------------------------

AGENT_RUNNERS = {
    "network-recon": runner.run_network_recon,
    "vuln-scanner": runner.run_vuln_scanner,
    "config-audit": runner.run_config_audit,
}


def _get_verified_asset_or_404(asset_id: str, db: Session) -> models.Asset:
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@app.post("/agents/{agent_name}/run/{asset_id}", response_model=schemas.AgentRunOut)
def run_agent_now(agent_name: str, asset_id: str, db: Session = Depends(get_db)):
    if agent_name not in AGENT_RUNNERS:
        raise HTTPException(404, f"Unknown agent '{agent_name}'. Valid: {list(AGENT_RUNNERS)}")
    asset = _get_verified_asset_or_404(asset_id, db)
    if asset.status != "verified":
        raise HTTPException(403, f"Asset '{asset.target}' is not verified -- refusing to scan.")
    run = AGENT_RUNNERS[agent_name](db, asset)
    return run


@app.post("/assets/{asset_id}/run-all", response_model=list[schemas.AgentRunOut])
def run_all_agents_now(asset_id: str, db: Session = Depends(get_db)):
    asset = _get_verified_asset_or_404(asset_id, db)
    if asset.status != "verified":
        raise HTTPException(403, f"Asset '{asset.target}' is not verified -- refusing to scan.")
    return runner.run_all_for_asset(db, asset)


@app.get("/agents/runs", response_model=list[schemas.AgentRunOut])
def list_agent_runs(agent: str | None = None, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(models.AgentRun)
    if agent:
        q = q.filter(models.AgentRun.agent == agent)
    return q.order_by(models.AgentRun.started_at.desc()).limit(limit).all()
