"""Pydantic models for the miner data structures."""

from __future__ import annotations

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
            "summary": self.summary.model_dump(),
            "repositories": [r.model_dump() for r in repos],
        }
