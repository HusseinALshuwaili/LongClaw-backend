"""
Alert Enrichment Service
Queries (mocked) external sources to give the FP scorer context.
Replace mock_* functions with real API calls in production.
"""
from __future__ import annotations

import asyncio
import random
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

# Known assets list — simulate an Asset Inventory database
_KNOWN_SERVERS = {
    "dc01.corp.local", "dc02.corp.local", "web01.corp.local",
    "backup01.corp.local", "siem01.corp.local", "jenkins01.corp.local",
}

# Simulated department directory
_USER_DEPARTMENTS = {
    "jsmith": "IT Operations",
    "adoe": "IT Operations",
    "bwilson": "DevOps",
    "mchen": "Finance",
    "rlee": "HR",
    "nkumar": "Security",
    "tjones": "IT Operations",
    "sgarcia": "Sales",
}

# Simulated threat intel scores (0 = benign, 100 = malicious)
_THREAT_INTEL_SCORES = {
    "8.8.8.8": 0,
    "1.1.1.1": 0,
    "192.0.2.1": 85,   # doc range — treat as suspicious
    "198.51.100.5": 92, # known bad in our mock
    "203.0.113.45": 78,
}


async def mock_ad_lookup(username: str) -> dict[str, Any]:
    """Simulate Active Directory / Okta user lookup."""
    await asyncio.sleep(0.01)  # simulate I/O latency
    dept = _USER_DEPARTMENTS.get(username.lower(), "Unknown")
    return {
        "username": username,
        "department": dept,
        "title": "Engineer" if dept == "IT Operations" else "Staff",
        "found": dept != "Unknown",
    }


async def mock_asset_lookup(hostname: str) -> dict[str, Any]:
    """Simulate Asset Inventory lookup."""
    await asyncio.sleep(0.01)
    is_known = hostname.lower() in _KNOWN_SERVERS
    return {
        "hostname": hostname,
        "is_known_server": is_known,
        "asset_type": "server" if is_known else "workstation",
        "criticality": "high" if is_known else "medium",
    }


async def mock_threat_intel(ip: str) -> dict[str, Any]:
    """Simulate VirusTotal / threat intel lookup."""
    await asyncio.sleep(0.02)
    score = _THREAT_INTEL_SCORES.get(ip, random.randint(0, 30))
    return {
        "ip": ip,
        "threat_score": score,
        "is_malicious": score >= 70,
        "categories": ["malware_distribution"] if score >= 70 else [],
    }


async def enrich_alert(raw_data: dict[str, Any]) -> dict[str, Any]:
    """
    Run all enrichment sources concurrently and merge results.
    Returns an enrichment dict that the FP scorer reads.
    """
    username = raw_data.get("username", raw_data.get("user", ""))
    hostname = raw_data.get("hostname", raw_data.get("host", ""))
    ip = raw_data.get("src_ip", raw_data.get("dest_ip", raw_data.get("ip", "")))

    tasks: list[Any] = []
    labels: list[str] = []

    if username:
        tasks.append(mock_ad_lookup(username))
        labels.append("ad")
    if hostname:
        tasks.append(mock_asset_lookup(hostname))
        labels.append("asset")
    if ip:
        tasks.append(mock_threat_intel(ip))
        labels.append("threat_intel")

    results: dict[str, Any] = {}
    if tasks:
        outputs = await asyncio.gather(*tasks, return_exceptions=True)
        for label, output in zip(labels, outputs):
            if isinstance(output, Exception):
                logger.warning("enrichment_source_failed", source=label, error=str(output))
            else:
                results[label] = output

    enrichment: dict[str, Any] = {
        "user_department": results.get("ad", {}).get("department"),
        "asset_is_known_server": results.get("asset", {}).get("is_known_server", False),
        "asset_criticality": results.get("asset", {}).get("criticality"),
        "threat_intel_score": results.get("threat_intel", {}).get("threat_score", 0),
        "threat_is_malicious": results.get("threat_intel", {}).get("is_malicious", False),
        "raw": results,
    }

    logger.info("alert_enriched", user_dept=enrichment["user_department"],
                known_server=enrichment["asset_is_known_server"],
                ti_score=enrichment["threat_intel_score"])
    return enrichment
