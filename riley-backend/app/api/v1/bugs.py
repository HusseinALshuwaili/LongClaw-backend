"""
Bug Scanner API — exposes the 3-agent bug detection pipeline.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.agents.bug_detector import scan_code, scan_github
from app.core.logging import get_logger

router = APIRouter(prefix="/bugs", tags=["Bug Scanner"])
logger = get_logger(__name__)


class CodeScanRequest(BaseModel):
    code: str = Field(..., min_length=10, description="Source code to scan")
    language: str = Field(default="", description="Programming language hint (e.g. python, javascript)")
    filename: str = Field(default="snippet", description="Optional filename for context")


class GitHubScanRequest(BaseModel):
    github_url: str = Field(..., description="Public GitHub repo or file URL")


@router.post(
    "/scan/code",
    summary="Scan a pasted code snippet for bugs",
    status_code=status.HTTP_200_OK,
)
async def scan_code_endpoint(body: CodeScanRequest):
    """
    Run the 3-agent bug detection pipeline on a pasted code snippet.
    Returns confirmed findings with severity, description, and suggested fix.
    """
    logger.info("bug_scan_code", filename=body.filename, language=body.language)
    result = await scan_code(
        code=body.code,
        language=body.language,
        filename=body.filename,
    )
    return result.to_dict()


@router.post(
    "/scan/github",
    summary="Scan a public GitHub repository for bugs",
    status_code=status.HTTP_200_OK,
)
async def scan_github_endpoint(body: GitHubScanRequest):
    """
    Clone (via GitHub API) and scan a public GitHub repository.
    Scans up to 12 source files. Returns confirmed findings.
    """
    logger.info("bug_scan_github", url=body.github_url)
    result = await scan_github(github_url=body.github_url)
    return result.to_dict()
