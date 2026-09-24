"""Tests for Pydantic models."""

from datetime import datetime, timezone

from miner.models import (
    AnalysisSummary,
    Finding,
    OrganizationReport,
    RepoStatus,
    RepositoryResult,
    SbomReport,
    SbomResult,
    SbomStatus,
    SbomSummary,
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


NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)


def test_sbom_status_enum():
    assert SbomStatus.SUCCESS.value == "success"
    assert SbomStatus.NO_COMPONENTS.value == "no_components"
    assert SbomStatus.FAILED.value == "failed"


def test_sbom_result_defaults():
    r = SbomResult(
        full_name="org/repo",
        generated_at=NOW,
        syft_version="1.15.1",
        status=SbomStatus.SUCCESS,
    )
    assert r.commit is None
    assert r.components == 0
    assert r.sbom_path is None
    assert r.error_message is None


def test_sbom_result_full():
    r = SbomResult(
        full_name="OWASP/NodeGoat",
        commit="a" * 40,
        generated_at=NOW,
        syft_version="1.15.1",
        status=SbomStatus.SUCCESS,
        components=42,
        sbom_path="sboms/NodeGoat.cdx.json",
    )
    assert r.full_name == "OWASP/NodeGoat"
    assert r.commit == "a" * 40
    assert r.components == 42
    assert r.sbom_path == "sboms/NodeGoat.cdx.json"


def test_sbom_result_no_components_is_not_failed():
    """A successful run with 0 components must not be confused with a failure."""
    no_components = SbomResult(
        full_name="org/empty",
        generated_at=NOW,
        syft_version="1.15.1",
        status=SbomStatus.NO_COMPONENTS,
        components=0,
        sbom_path="sboms/empty.cdx.json",
    )
    failed = SbomResult(
        full_name="org/broken",
        generated_at=NOW,
        syft_version="1.15.1",
        status=SbomStatus.FAILED,
        error_message="syft crashed",
    )
    assert no_components.status != failed.status
    assert no_components.error_message is None
    assert failed.error_message == "syft crashed"


def test_sbom_summary():
    s = SbomSummary(
        repositories=17,
        success=12,
        no_components=3,
        failed=2,
        components=842,
    )
    assert s.repositories == 17
    assert s.components == 842
    assert s.success + s.no_components + s.failed == s.repositories


def test_sbom_report_to_ordered_json():
    repos = [
        SbomResult(
            full_name="org/zeta",
            generated_at=NOW,
            syft_version="1.15.1",
            status=SbomStatus.FAILED,
            error_message="clone not found",
        ),
        SbomResult(
            full_name="org/alpha",
            commit="b" * 40,
            generated_at=NOW,
            syft_version="1.15.1",
            status=SbomStatus.SUCCESS,
            components=7,
            sbom_path="sboms/alpha.cdx.json",
        ),
    ]
    report = SbomReport(
        organization="org",
        generated_at=NOW,
        syft_version="1.15.1",
        summary=SbomSummary(
            repositories=2, success=1, no_components=0, failed=1, components=7,
        ),
        repositories=repos,
    )
    d = report.to_ordered_json()

    assert d["organization"] == "org"
    assert d["generated_at"] == NOW.isoformat()
    assert d["syft_version"] == "1.15.1"
    assert d["repositories"][0]["full_name"] == "org/alpha"
    assert d["repositories"][1]["full_name"] == "org/zeta"
    assert d["repositories"][0]["status"] == "success"
    assert d["repositories"][1]["status"] == "failed"
    assert d["summary"]["components"] == 7


def test_repository_result_without_sbom():
    r = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status=RepoStatus.ANALYZED,
    )
    assert r.sbom is None


def test_repository_result_with_sbom():
    sbom = SbomResult(
        full_name="org/test-repo",
        generated_at=NOW,
        syft_version="1.15.1",
        status=SbomStatus.SUCCESS,
        components=5,
        sbom_path="sboms/test-repo.cdx.json",
    )
    r = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status=RepoStatus.ANALYZED,
        sbom=sbom,
    )
    assert r.sbom is not None
    assert r.sbom.status == SbomStatus.SUCCESS
    assert r.sbom.components == 5
