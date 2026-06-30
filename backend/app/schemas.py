from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, Field


# ---------- Alerts / Triage ----------

class AlertIngest(BaseModel):
    source: str = Field(..., examples=["EDR", "SIEM", "PHISHING_DEFENSE"])
    description: str
    raw_payload: Optional[dict] = None


class AlertOut(BaseModel):
    id: str
    source: str
    description: str
    status: str
    severity: Optional[str] = None
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    suggested_action: Optional[str] = None
    resolution: Optional[str] = None
    created_at: datetime
    classified_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ResolveRequest(BaseModel):
    resolved_by: str = "operator@local"


class KPIOut(BaseModel):
    ingested_24h: int
    sent_to_queue: int
    awaiting_review: int
    noise_reduced_pct: float


# ---------- Triage classification (structured output contract) ----------

class TriageClassification(BaseModel):
    severity: Literal["high", "med", "low"]
    confidence: float = Field(ge=0, le=1)
    rationale: str
    suggested_action: Literal["escalate", "dismiss"]


# ---------- Assets ----------

class AssetRegister(BaseModel):
    target: str
    asset_type: Literal["domain", "ip_range", "aws_account"]
    owner_email: str
    verification_method: Literal["dns_txt", "iam_role"] = "dns_txt"


class AssetOut(BaseModel):
    id: str
    target: str
    asset_type: str
    owner_email: str
    verification_method: str
    verification_token: str
    status: str
    created_at: datetime
    verified_at: Optional[datetime] = None
    last_scanned_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- Tactical agent runs ----------

class AgentRunOut(BaseModel):
    id: str
    agent: str
    asset_id: Optional[str] = None
    asset_target: Optional[str] = None
    status: str
    summary: Optional[str] = None
    alert_id: Optional[str] = None
    started_at: datetime
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True
