import uuid
from datetime import datetime

from sqlalchemy import Column, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


def gen_id() -> str:
    return uuid.uuid4().hex[:12]


class Alert(Base):
    """A raw security event ingested from a source tool, plus the Triage
    Agent's classification once it has been processed."""

    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=gen_id)
    source = Column(String, nullable=False)            # e.g. "EDR", "SIEM", "PHISHING_DEFENSE"
    description = Column(Text, nullable=False)
    raw_payload = Column(Text, nullable=True)           # original JSON, stored as text

    # Triage output
    status = Column(String, default="pending")          # pending | classified | escalated | dismissed
    severity = Column(String, nullable=True)             # high | med | low
    confidence = Column(Float, nullable=True)
    rationale = Column(Text, nullable=True)
    suggested_action = Column(String, nullable=True)     # escalate | dismiss

    # human decision
    resolution = Column(String, nullable=True)           # escalated | dismissed
    resolved_by = Column(String, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    classified_at = Column(DateTime, nullable=True)


class Asset(Base):
    """Registry entry for an asset a customer wants tactical agents to be
    allowed to scan. Nothing is scanned until status == 'verified'."""

    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=gen_id)
    target = Column(String, nullable=False)              # hostname, domain, or ARN
    asset_type = Column(String, nullable=False)          # domain | ip_range | aws_account
    owner_email = Column(String, nullable=False)
    verification_method = Column(String, default="dns_txt")  # dns_txt | iam_role
    verification_token = Column(String, default=gen_id)
    status = Column(String, default="pending")           # pending | verified | failed
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)

    # tactical agent state
    scan_baseline = Column(Text, nullable=True)           # JSON list of last-seen open ports (Network Recon)
    last_scanned_at = Column(DateTime, nullable=True)


class AgentRun(Base):
    """Audit log of every tactical agent execution -- what ran, against
    what asset, when, and what it found. Powers the dashboard's agent
    health panel and gives you a real record for compliance evidence."""

    __tablename__ = "agent_runs"

    id = Column(String, primary_key=True, default=gen_id)
    agent = Column(String, nullable=False)        # network-recon | vuln-scanner | config-audit
    asset_id = Column(String, nullable=True)
    asset_target = Column(String, nullable=True)
    status = Column(String, default="ok")          # ok | error | skipped_unverified
    summary = Column(Text, nullable=True)
    alert_id = Column(String, nullable=True)        # set if this run produced an alert
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
