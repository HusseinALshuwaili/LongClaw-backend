"""
Tests for Riley's FP scoring engine.
Run with: pytest tests/test_fp_scorer.py -v
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.fp_scorer import _apply_rules, _is_business_hours, score_alert
from app.services.pattern_engine import extract_signature


# ── _is_business_hours ───────────────────────────────────────────────────────

def test_business_hours_weekday_9am():
    dt = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday 09:00
    assert _is_business_hours(dt) is True


def test_business_hours_weekday_7pm():
    dt = datetime(2024, 1, 15, 19, 0, tzinfo=timezone.utc)  # Monday 19:00
    assert _is_business_hours(dt) is False


def test_business_hours_saturday():
    dt = datetime(2024, 1, 13, 10, 0, tzinfo=timezone.utc)  # Saturday 10:00
    assert _is_business_hours(dt) is False


def test_business_hours_none():
    assert _is_business_hours(None) is True  # default to True = benefit of doubt


# ── _apply_rules ─────────────────────────────────────────────────────────────

def _base_raw(alert_type: str = "generic", severity: str = "medium") -> dict:
    return {"alert_type": alert_type, "severity": severity, "username": "testuser"}


def test_itops_powershell_fires():
    enrichment = {"user_department": "IT Operations", "asset_is_known_server": False,
                  "threat_intel_score": 0}
    raw = _base_raw("powershell_execution", "high")
    dt = datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)  # business hours
    delta, reasons = _apply_rules(raw, enrichment, "powershell_execution", "high", dt)
    assert delta >= 40, "IT Ops PowerShell during biz hours should add +40"
    assert any("IT Ops" in r for r in reasons)


def test_threat_intel_high_reduces_score():
    enrichment = {"user_department": "Unknown", "asset_is_known_server": False,
                  "threat_intel_score": 85}
    raw = _base_raw("lateral_movement", "critical")
    delta, reasons = _apply_rules(raw, enrichment, "lateral_movement", "critical", None)
    assert delta <= -40, "High threat intel should reduce score significantly"
    assert any("threat" in r.lower() for r in reasons)


def test_critical_after_hours_reduces_score():
    enrichment = {"user_department": "IT Operations", "asset_is_known_server": False,
                  "threat_intel_score": 0}
    raw = _base_raw("brute_force", "critical")
    dt = datetime(2024, 1, 15, 2, 0, tzinfo=timezone.utc)  # 2 AM
    delta, reasons = _apply_rules(raw, enrichment, "brute_force", "critical", dt)
    assert delta < 0, "Critical alert at 2 AM should not be favoured as FP"


def test_backup_job_increases_score():
    enrichment = {"user_department": "IT Operations", "asset_is_known_server": True,
                  "threat_intel_score": 0}
    raw = {"alert_type": "process_creation", "severity": "low",
           "username": "adoe", "process_args": "veeam backup run --job nightly"}
    delta, reasons = _apply_rules(raw, enrichment, "process_creation", "low", None)
    assert delta > 0, "Backup job pattern should push score toward FP"


def test_known_server_low_severity():
    enrichment = {"user_department": None, "asset_is_known_server": True,
                  "threat_intel_score": 0}
    raw = _base_raw("generic_alert", "info")
    delta, reasons = _apply_rules(raw, enrichment, "generic_alert", "info", None)
    assert delta >= 25


# ── extract_signature ─────────────────────────────────────────────────────────

def test_signature_normalises_ips():
    raw = {"username": "jsmith", "src_ip": "10.0.1.5", "dest_ip": "192.168.1.100"}
    sig = extract_signature("powershell_execution", raw)
    serialised = str(sig["normalised_payload"])
    assert "10.0.1.5" not in serialised
    assert "<IP>" in serialised


def test_signature_normalises_timestamps():
    raw = {"timestamp": "2024-01-15T09:30:00Z", "username": "jsmith"}
    sig = extract_signature("test_alert", raw)
    serialised = str(sig["normalised_payload"])
    assert "2024-01-15T09:30:00Z" not in serialised
    assert "<TIMESTAMP>" in serialised


def test_signature_has_hash():
    raw = {"username": "jsmith", "process": "powershell.exe"}
    sig = extract_signature("powershell_execution", raw)
    assert "sig_hash" in sig
    assert len(sig["sig_hash"]) == 16


def test_signature_deterministic():
    raw = {"username": "jsmith", "src_ip": "10.0.1.5"}
    sig1 = extract_signature("ps_exec", raw)
    sig2 = extract_signature("ps_exec", raw)
    assert sig1["sig_hash"] == sig2["sig_hash"]


# ── Full score_alert integration (no real DB — uses in-memory via fixture) ────

@pytest.mark.anyio
async def test_score_alert_itops_returns_high_fp_confidence(db):
    """IT Ops PowerShell during business hours should score > 60 FP confidence."""
    enrichment = {
        "user_department": "IT Operations",
        "asset_is_known_server": True,
        "threat_intel_score": 0,
        "threat_is_malicious": False,
    }
    raw = {"username": "jsmith", "hostname": "dc01.corp.local",
           "command": "powershell.exe -File backup.ps1"}
    sig = extract_signature("powershell_execution", raw)
    dt = datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)

    result = await score_alert(
        alert_type="powershell_execution",
        severity="high",
        raw_data=raw,
        enrichment=enrichment,
        signature=sig,
        created_at=dt,
        analyst_comments=None,
        db=db,
    )
    assert result.fp_confidence >= 60.0, (
        f"IT Ops PowerShell should have FP confidence >= 60, got {result.fp_confidence}"
    )


@pytest.mark.anyio
async def test_score_alert_threat_intel_returns_low_fp_confidence(db):
    """High threat intel score should produce low FP confidence (i.e., likely TP)."""
    enrichment = {
        "user_department": None,
        "asset_is_known_server": False,
        "threat_intel_score": 90,
        "threat_is_malicious": True,
    }
    raw = {"username": "unknown_user", "src_ip": "198.51.100.5",
           "process": "mimikatz.exe"}
    sig = extract_signature("credential_dump", raw)

    result = await score_alert(
        alert_type="credential_dump",
        severity="critical",
        raw_data=raw,
        enrichment=enrichment,
        signature=sig,
        created_at=None,
        analyst_comments=None,
        db=db,
    )
    assert result.fp_confidence < 60.0, (
        f"Mimikatz from unknown IP with 90 TI score should be low FP confidence, "
        f"got {result.fp_confidence}"
    )
    assert result.action == "ESCALATE"
