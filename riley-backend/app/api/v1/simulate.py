"""
Simulation Mode — POST /simulate
Runs a batch of labelled mock alerts through Riley and reports accuracy.
Used for demos, internal testing, and the brag sheet.
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.database import get_db
from app.services.enrichment import enrich_alert
from app.services.fp_scorer import score_alert
from app.services.pattern_engine import extract_signature

router = APIRouter(prefix="/simulate", tags=["Simulation"])
logger = get_logger(__name__)

DB = Annotated[AsyncSession, Depends(get_db)]

# ── Mock alert dataset with ground-truth labels ───────────────────────────────
# label: "fp" = definitely false positive, "tp" = true positive
_MOCK_ALERTS: list[dict[str, Any]] = [
    {
        "source_system": "crowdstrike",
        "alert_type": "powershell_execution",
        "severity": "high",
        "label": "fp",
        "raw_data": {
            "username": "jsmith",
            "hostname": "dc01.corp.local",
            "command": "powershell.exe -ExecutionPolicy Bypass -File backup.ps1",
            "src_ip": "10.0.1.5",
            "process": "powershell.exe",
        },
    },
    {
        "source_system": "splunk",
        "alert_type": "lateral_movement",
        "severity": "critical",
        "label": "tp",
        "raw_data": {
            "username": "sgarcia",
            "hostname": "wks-sales-03",
            "src_ip": "198.51.100.5",
            "dest_ip": "10.0.2.10",
            "technique": "pass_the_hash",
        },
    },
    {
        "source_system": "sentinel",
        "alert_type": "scheduled_task_creation",
        "severity": "medium",
        "label": "fp",
        "raw_data": {
            "username": "adoe",
            "hostname": "jenkins01.corp.local",
            "task_name": "nightly_patching",
            "src_ip": "10.0.1.20",
        },
    },
    {
        "source_system": "crowdstrike",
        "alert_type": "credential_dump",
        "severity": "critical",
        "label": "tp",
        "raw_data": {
            "username": "mchen",
            "hostname": "wks-fin-07",
            "process": "mimikatz.exe",
            "src_ip": "192.0.2.1",
        },
    },
    {
        "source_system": "elastic",
        "alert_type": "powershell_encoded_command",
        "severity": "high",
        "label": "fp",
        "raw_data": {
            "username": "bwilson",
            "hostname": "web01.corp.local",
            "src_ip": "10.0.3.1",
            "encoded_cmd": "JABzAD0ATgBlAHcA...",
        },
    },
    {
        "source_system": "sentinel",
        "alert_type": "data_exfiltration",
        "severity": "critical",
        "label": "tp",
        "raw_data": {
            "username": "rlee",
            "hostname": "wks-hr-02",
            "bytes_out": 524288000,
            "dest_ip": "203.0.113.45",
        },
    },
    {
        "source_system": "splunk",
        "alert_type": "vulnerability_scan",
        "severity": "low",
        "label": "fp",
        "raw_data": {
            "username": "nkumar",
            "hostname": "siem01.corp.local",
            "scanner_tool": "nmap",
            "src_ip": "10.0.0.5",
        },
    },
    {
        "source_system": "crowdstrike",
        "alert_type": "ransomware_behavior",
        "severity": "critical",
        "label": "tp",
        "raw_data": {
            "username": "unknown_user",
            "hostname": "wks-acct-11",
            "extensions_encrypted": 342,
            "src_ip": "198.51.100.5",
        },
    },
    {
        "source_system": "elastic",
        "alert_type": "script_block_logging",
        "severity": "medium",
        "label": "fp",
        "raw_data": {
            "username": "tjones",
            "hostname": "dc02.corp.local",
            "script_name": "deploy_patches.ps1",
            "src_ip": "10.0.1.7",
        },
    },
    {
        "source_system": "sentinel",
        "alert_type": "port_scan",
        "severity": "medium",
        "label": "fp",
        "raw_data": {
            "username": "nkumar",
            "hostname": "siem01.corp.local",
            "scan_type": "compliance_check",
            "target_range": "10.0.0.0/24",
        },
    },
]


@router.post("/", summary="Run simulation with labelled mock alerts")
async def run_simulation(db: DB) -> dict[str, Any]:
    """
    Fires all built-in mock alerts through Riley's scoring engine.
    Compares Riley's verdict against ground-truth labels and returns accuracy metrics.
    Useful for demos and accuracy benchmarking.
    """
    results: list[dict[str, Any]] = []
    correct = 0
    total = len(_MOCK_ALERTS)

    for mock in _MOCK_ALERTS:
        enrichment = await enrich_alert(mock["raw_data"])
        signature = extract_signature(mock["alert_type"], mock["raw_data"])

        scored = await score_alert(
            alert_type=mock["alert_type"],
            severity=mock["severity"],
            raw_data=mock["raw_data"],
            enrichment=enrichment,
            signature=signature,
            created_at=None,
            analyst_comments=None,
            db=db,
        )

        riley_verdict = "fp" if scored.fp_confidence >= 60 else "tp"
        ground_truth = mock["label"]
        is_correct = riley_verdict == ground_truth

        if is_correct:
            correct += 1

        results.append({
            "alert_type": mock["alert_type"],
            "severity": mock["severity"],
            "ground_truth": ground_truth,
            "riley_verdict": riley_verdict,
            "fp_confidence": scored.fp_confidence,
            "action": scored.action,
            "correct": is_correct,
            "reason": scored.reason[:120] + "..." if len(scored.reason) > 120 else scored.reason,
        })

    accuracy = round(correct / total * 100, 1)
    fps_in_set = sum(1 for r in _MOCK_ALERTS if r["label"] == "fp")
    riley_fp_correct = sum(1 for r in results if r["ground_truth"] == "fp" and r["correct"])

    logger.info("simulation_complete", accuracy=accuracy, correct=correct, total=total)

    return {
        "summary": {
            "total_alerts": total,
            "correct": correct,
            "incorrect": total - correct,
            "accuracy_pct": accuracy,
            "fp_recall": round(riley_fp_correct / fps_in_set * 100, 1) if fps_in_set else 0,
            "verdict": "🟢 Riley is production-ready" if accuracy >= 80 else "🟡 Needs more training data",
        },
        "results": results,
    }
