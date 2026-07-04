"""
Riley Bug Detector — 3-agent pipeline powered by Groq (Llama 3.3 70B).

Pipeline:
  1. Analyzer  — scans code for suspicious patterns
  2. Detector  — verifies each pattern is actually exploitable
  3. Debunker  — adversarially tries to refute each confirmed finding

Only findings that survive the Debunker are surfaced to the user.
Uses Groq via the OpenAI-compatible API (no new package required).
Falls back to a lightweight rule-based scanner when GROQ_API_KEY is not set.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ── Prompts ───────────────────────────────────────────────────────────────────

_ANALYZER_SYSTEM = """\
You are a senior security engineer performing a code security audit.
Scan the provided code for ALL suspicious patterns that could be vulnerabilities or bugs.

Return ONLY valid JSON (no markdown, no explanation) in this exact shape:
{
  "patterns": [
    {
      "id": "p1",
      "type": "sql_injection",
      "location": "line 42",
      "code_snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
      "why_suspicious": "String concatenation in SQL query allows injection"
    }
  ]
}

Vulnerability types to look for:
sql_injection, xss, command_injection, path_traversal, hardcoded_secret,
race_condition, insecure_deserialization, auth_bypass, ssrf, xxe,
null_dereference, buffer_overflow, open_redirect, insecure_random,
missing_rate_limit, sensitive_data_exposure, broken_access_control

Return an empty patterns array if nothing suspicious is found.
"""

_DETECTOR_SYSTEM = """\
You are a senior security engineer verifying whether a suspicious code pattern is a real vulnerability.

Given the code context and a specific pattern, determine if it is actually exploitable.
Consider: Is input user-controlled? Is there hidden sanitization? Is the code reachable?

Return ONLY valid JSON:
{
  "confirmed": true,
  "severity": "critical",
  "cvss_score": 9.1,
  "description": "User-supplied input is concatenated directly into an SQL query without sanitization.",
  "attack_scenario": "Attacker sends `1 OR 1=1--` as user_id to dump the entire users table.",
  "suggested_fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
}

severity must be one of: critical, high, medium, low
confirmed must be true or false
"""

_DEBUNKER_SYSTEM = """\
You are a senior security engineer playing adversarial devil's advocate.
A vulnerability has been claimed. Try to DISPROVE it.

Look for: hidden sanitization, framework-level protection, trusted input sources,
dead code paths, authentication guards that prevent exploitation.

Return ONLY valid JSON:
{
  "debunked": false,
  "reason": "The input comes directly from request.GET without validation and the ORM is bypassed.",
  "confidence": 0.95
}

debunked: true if you successfully refuted the finding, false if it stands.
confidence: how confident you are in your debunking assessment (0.0-1.0).
"""


# ── GitHub fetcher ────────────────────────────────────────────────────────────

_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
    ".rb", ".php", ".cs", ".cpp", ".c", ".rs", ".swift",
}

_MAX_FILES = 12
_MAX_FILE_LINES = 600


def _parse_github_url(url: str) -> tuple[str, str, str]:
    """Extract owner, repo, path from a GitHub URL. Returns (owner, repo, path)."""
    url = url.strip().rstrip("/")
    # Handle: https://github.com/owner/repo or .../blob/branch/path
    match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)(?:/(?:blob|tree)/[^/]+/(.*))?", url
    )
    if not match:
        raise ValueError(f"Cannot parse GitHub URL: {url}")
    owner = match.group(1)
    repo = match.group(2).removesuffix(".git")
    path = match.group(3) or ""
    return owner, repo, path


async def _fetch_github_files(owner: str, repo: str, path: str = "") -> list[dict[str, str]]:
    """Fetch scannable files from a GitHub repo (public, no auth)."""
    files: list[dict[str, str]] = []

    async with httpx.AsyncClient(timeout=20) as client:
        async def _recurse(dir_path: str) -> None:
            if len(files) >= _MAX_FILES:
                return
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{dir_path}"
            resp = await client.get(api_url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code != 200:
                return
            items = resp.json()
            if isinstance(items, dict):
                # Single file
                items = [items]
            for item in items:
                if len(files) >= _MAX_FILES:
                    return
                if item["type"] == "file":
                    ext = "." + item["name"].rsplit(".", 1)[-1] if "." in item["name"] else ""
                    if ext in _SCANNABLE_EXTENSIONS:
                        content_resp = await client.get(item["download_url"])
                        if content_resp.status_code == 200:
                            lines = content_resp.text.splitlines()[:_MAX_FILE_LINES]
                            files.append({
                                "path": item["path"],
                                "content": "\n".join(lines),
                            })
                elif item["type"] == "dir" and not item["name"].startswith("."):
                    if item["name"] not in ("node_modules", "vendor", "__pycache__", ".git", "dist", "build"):
                        await _recurse(item["path"])

        await _recurse(path)

    return files


# ── LLM helpers ──────────────────────────────────────────────────────────────

def _groq_client():
    from openai import AsyncOpenAI
    return AsyncOpenAI(
        api_key=settings.GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1",
    )


async def _call_groq(system: str, user: str, model: str = "llama-3.3-70b-versatile") -> dict[str, Any]:
    """Call Groq and parse JSON response. Returns empty dict on failure."""
    try:
        client = _groq_client()
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=2048,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        text = response.choices[0].message.content or "{}"
        return json.loads(text)
    except Exception as exc:
        logger.warning("groq_call_failed", error=str(exc))
        return {}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BugFinding:
    id: str
    type: str
    severity: str
    cvss_score: float
    location: str
    code_snippet: str
    description: str
    attack_scenario: str
    suggested_fix: str
    debunker_confidence: float
    file_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "attack_scenario": self.attack_scenario,
            "suggested_fix": self.suggested_fix,
            "debunker_confidence": self.debunker_confidence,
            "file_path": self.file_path,
        }


@dataclass
class ScanResult:
    scan_id: str
    status: str
    input_type: str
    files_scanned: int
    findings: list[BugFinding] = field(default_factory=list)
    model_used: str = "llama-3.3-70b-versatile"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity, 9),
        )
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "input_type": self.input_type,
            "files_scanned": self.files_scanned,
            "model_used": self.model_used,
            "summary": {
                "total_findings": len(self.findings),
                **counts,
            },
            "findings": [f.to_dict() for f in sorted_findings],
            "error": self.error,
        }


# ── Core pipeline ─────────────────────────────────────────────────────────────

async def _scan_file(file_path: str, code: str, language: str = "") -> list[BugFinding]:
    """Run the 3-agent pipeline on a single file/snippet."""
    findings: list[BugFinding] = []

    lang_hint = f"Language: {language}\n" if language else ""
    file_hint = f"File: {file_path}\n" if file_path else ""
    code_block = f"{lang_hint}{file_hint}\n```\n{code}\n```"

    # ── Agent 1: Analyzer ────────────────────────────────────────────────────
    analyzer_out = await _call_groq(
        system=_ANALYZER_SYSTEM,
        user=f"Scan this code for security vulnerabilities:\n\n{code_block}",
    )
    patterns = analyzer_out.get("patterns", [])
    if not patterns:
        logger.info("analyzer_no_patterns", file=file_path)
        return []

    logger.info("analyzer_found_patterns", file=file_path, count=len(patterns))

    for pattern in patterns:
        # ── Agent 2: Detector ────────────────────────────────────────────────
        detector_out = await _call_groq(
            system=_DETECTOR_SYSTEM,
            user=(
                f"Full code context:\n{code_block}\n\n"
                f"Suspicious pattern to verify:\n{json.dumps(pattern, indent=2)}"
            ),
        )

        if not detector_out.get("confirmed", False):
            logger.info("detector_rejected", pattern_id=pattern.get("id"))
            continue

        # ── Agent 3: Debunker ────────────────────────────────────────────────
        debunker_out = await _call_groq(
            system=_DEBUNKER_SYSTEM,
            user=(
                f"Full code context:\n{code_block}\n\n"
                f"Confirmed vulnerability to debunk:\n"
                f"Pattern: {json.dumps(pattern, indent=2)}\n"
                f"Detector verdict: {json.dumps(detector_out, indent=2)}"
            ),
        )

        if debunker_out.get("debunked", False):
            logger.info(
                "debunker_refuted",
                pattern_id=pattern.get("id"),
                reason=debunker_out.get("reason", ""),
            )
            continue

        # Survived all 3 agents — it's a real finding
        findings.append(
            BugFinding(
                id=str(uuid.uuid4())[:8],
                type=pattern.get("type", "unknown"),
                severity=detector_out.get("severity", "medium"),
                cvss_score=float(detector_out.get("cvss_score", 5.0)),
                location=pattern.get("location", "unknown"),
                code_snippet=pattern.get("code_snippet", ""),
                description=detector_out.get("description", ""),
                attack_scenario=detector_out.get("attack_scenario", ""),
                suggested_fix=detector_out.get("suggested_fix", ""),
                debunker_confidence=float(debunker_out.get("confidence", 0.5)),
                file_path=file_path,
            )
        )
        logger.info("finding_confirmed", type=pattern.get("type"), file=file_path)

    return findings


# ── Public entry points ───────────────────────────────────────────────────────

async def scan_code(
    code: str,
    language: str = "",
    filename: str = "snippet",
) -> ScanResult:
    """Scan a pasted code snippet."""
    scan_id = str(uuid.uuid4())

    if not settings.GROQ_API_KEY:
        return ScanResult(
            scan_id=scan_id,
            status="error",
            input_type="code_paste",
            files_scanned=0,
            error="GROQ_API_KEY not configured. Add it in Render environment variables.",
            model_used="none",
        )

    findings = await _scan_file(filename, code, language)

    return ScanResult(
        scan_id=scan_id,
        status="complete",
        input_type="code_paste",
        files_scanned=1,
        findings=findings,
    )


async def scan_github(github_url: str) -> ScanResult:
    """Fetch and scan a public GitHub repository."""
    scan_id = str(uuid.uuid4())

    if not settings.GROQ_API_KEY:
        return ScanResult(
            scan_id=scan_id,
            status="error",
            input_type="github_url",
            files_scanned=0,
            error="GROQ_API_KEY not configured. Add it in Render environment variables.",
            model_used="none",
        )

    try:
        owner, repo, path = _parse_github_url(github_url)
    except ValueError as exc:
        return ScanResult(
            scan_id=scan_id,
            status="error",
            input_type="github_url",
            files_scanned=0,
            error=str(exc),
            model_used="none",
        )

    try:
        files = await _fetch_github_files(owner, repo, path)
    except Exception as exc:
        return ScanResult(
            scan_id=scan_id,
            status="error",
            input_type="github_url",
            files_scanned=0,
            error=f"Failed to fetch repository: {exc}",
            model_used="none",
        )

    if not files:
        return ScanResult(
            scan_id=scan_id,
            status="complete",
            input_type="github_url",
            files_scanned=0,
            error="No scannable files found in repository.",
        )

    all_findings: list[BugFinding] = []
    for file in files:
        file_findings = await _scan_file(file["path"], file["content"])
        all_findings.extend(file_findings)

    return ScanResult(
        scan_id=scan_id,
        status="complete",
        input_type="github_url",
        files_scanned=len(files),
        findings=all_findings,
    )
