"""Tests for Pydantic models."""

from miner.models import (
    AnalysisSummary,
    Finding,
    OrganizationReport,
    RepoStatus,
    RepositoryResult,
)


def test_finding_creation():
    f = Finding(
        rule_id="py/sql-injection",
        severity="warning",
        message="SQL injection risk",
        file="src/db.py",
        start_line=42,
    )
    assert f.rule_id == "py/sql-injection"
    assert f.severity == "warning"
    assert f.end_line is None
    assert f.code_snippet is None


def test_finding_with_optional_fields():
    f = Finding(
        rule_id="py/xss",
        severity="error",
        message="XSS vulnerability",
        file="src/web.py",
        start_line=10,
        end_line=15,
        code_snippet="return user_input",
    )
    assert f.end_line == 15
    assert f.code_snippet == "return user_input"


def test_repository_result_defaults():
    r = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status=RepoStatus.ANALYZED,
    )
    assert r.languages == []
    assert r.findings == []
    assert r.error_message is None


def test_repository_result_with_error():
    r = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status=RepoStatus.CLONE_FAILED,
        error_message="Connection refused",
    )
    assert r.status == RepoStatus.CLONE_FAILED
    assert r.error_message == "Connection refused"


def test_analysis_summary():
    s = AnalysisSummary(
        repositories=10,
        analyzed=8,
        clone_failed=1,
        unsupported=0,
        database_failed=0,
        analysis_failed=1,
        findings=15,
    )
    assert s.repositories == 10
    assert s.findings == 15


def test_organization_report_to_ordered_json():
    repos = [
        RepositoryResult(
            name="beta",
            url="https://github.com/org/beta",
            status=RepoStatus.ANALYZED,
            findings=[
                Finding(
                    rule_id="py/rule-b",
                    severity="warning",
                    message="msg b",
                    file="src/z.py",
                    start_line=5,
                ),
                Finding(
                    rule_id="py/rule-a",
                    severity="error",
                    message="msg a",
                    file="src/a.py",
                    start_line=1,
                ),
            ],
        ),
        RepositoryResult(
            name="alpha",
            url="https://github.com/org/alpha",
            status=RepoStatus.CLONE_FAILED,
            error_message="clone error",
        ),
    ]
    summary = AnalysisSummary(
        repositories=2,
        analyzed=1,
        clone_failed=1,
        unsupported=0,
        database_failed=0,
        analysis_failed=0,
        findings=2,
    )
    report = OrganizationReport(
        organization="org",
        summary=summary,
        repositories=repos,
    )
    d = report.to_ordered_json()

    assert d["organization"] == "org"
    assert d["repositories"][0]["name"] == "alpha"
    assert d["repositories"][1]["name"] == "beta"

    beta_findings = d["repositories"][1]["findings"]
    assert beta_findings[0]["file"] == "src/a.py"
    assert beta_findings[1]["file"] == "src/z.py"


def test_repo_status_enum():
    assert RepoStatus.ANALYZED.value == "analyzed"
    assert RepoStatus.CLONE_FAILED.value == "clone_failed"
    assert RepoStatus.UNSUPPORTED_LANGUAGE.value == "unsupported_language"
    assert RepoStatus.DATABASE_FAILED.value == "database_failed"
    assert RepoStatus.ANALYSIS_FAILED.value == "analysis_failed"


def test_organization_report_empty():
    report = OrganizationReport(
        organization="empty-org",
        summary=AnalysisSummary(
            repositories=0, analyzed=0, clone_failed=0,
            unsupported=0, database_failed=0, analysis_failed=0, findings=0,
        ),
    )
    d = report.to_ordered_json()
    assert d["repositories"] == []
    assert d["summary"]["repositories"] == 0
