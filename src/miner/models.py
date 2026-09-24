"""Pydantic models for the miner data structures."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RepoStatus(str, Enum):
    ANALYZED = "analyzed"
    CLONE_FAILED = "clone_failed"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    DATABASE_FAILED = "database_failed"
    ANALYSIS_FAILED = "analysis_failed"


class Finding(BaseModel):
    rule_id: str
    severity: str
    message: str
    file: str
    start_line: int
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None


class RepositoryResult(BaseModel):
    name: str
    url: str
    status: RepoStatus
    languages: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    error_message: Optional[str] = None
    sbom: Optional["SbomResult"] = None


class AnalysisSummary(BaseModel):
    repositories: int
    analyzed: int
    clone_failed: int
    unsupported: int
    database_failed: int
    analysis_failed: int
    findings: int


class OrganizationReport(BaseModel):
    organization: str
    summary: AnalysisSummary
    repositories: list[RepositoryResult] = Field(default_factory=list)

    def to_ordered_json(self) -> dict:
        repos = sorted(self.repositories, key=lambda r: r.name)
        for repo in repos:
            repo.findings = sorted(
                repo.findings,
                key=lambda f: (f.file, f.start_line, f.rule_id),
            )
        return {
            "organization": self.organization,
            "summary": self.summary.model_dump(mode="json"),
            "repositories": [r.model_dump(mode="json") for r in repos],
        }


class SbomStatus(str, Enum):
    """Execution state of the SBOM generation for a single repository."""

    SUCCESS = "success"
    NO_COMPONENTS = "no_components"
    FAILED = "failed"


class SbomResult(BaseModel):
    """SBOM generation result for a single repository."""

    full_name: str
    commit: Optional[str] = None
    generated_at: datetime
    syft_version: str
    status: SbomStatus
    components: int = 0
    sbom_path: Optional[str] = None
    error_message: Optional[str] = None


class SbomSummary(BaseModel):
    repositories: int
    success: int
    no_components: int
    failed: int
    components: int


class SbomReport(BaseModel):
    organization: str
    generated_at: datetime
    syft_version: str
    summary: SbomSummary
    repositories: list[SbomResult] = Field(default_factory=list)

    def to_ordered_json(self) -> dict:
        repos = sorted(self.repositories, key=lambda r: r.full_name)
        return {
            "organization": self.organization,
            "generated_at": self.generated_at.isoformat(),
            "syft_version": self.syft_version,
            "summary": self.summary.model_dump(mode="json"),
            "repositories": [r.model_dump(mode="json") for r in repos],
        }
