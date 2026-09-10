"""CLI interface using Typer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .codeql import create_database, detect_packs_root, run_analysis
from .github import fetch_languages, fetch_repos
from .git_ops import cleanup, clone_repo
from .models import (
    AnalysisSummary,
    OrganizationReport,
    RepoStatus,
    RepositoryResult,
)
from .sarif import parse_sarif

app = typer.Typer()
console = Console()

SUPPORTED_CODEQL_LANGUAGES = {
    "python", "java", "javascript", "typescript",
    "csharp", "cpp", "c", "go", "ruby", "swift",
}


@app.command()
def scan(
    organization: str = typer.Option(None, "--organization", "-o", help="GitHub organization name"),
    repo: str = typer.Option(None, "--repo", "-r", help="Single repository to scan (e.g. OWASP/NodeGoat or just NodeGoat with -o)"),
    output: str = typer.Option("results.json", "--output", "-O", help="Output JSON file path"),
    workdir: str = typer.Option(None, "--workdir", "-w", help="Working directory for clones and databases"),
    packs_root: str = typer.Option(None, "--packs-root", "-p", help="Path to CodeQL query packs (codeql-repo). Detected automatically if omitted."),
) -> None:
    """Scan a GitHub organization's repositories (or a single repo) for vulnerabilities using CodeQL."""

    if not organization and not repo:
        console.print("[bold red]Error:[/] Provide --organization and/or --repo.")
        raise typer.Exit(1)

    org_name, repo_name = _parse_target(organization, repo)

    packs = Path(packs_root) if packs_root else detect_packs_root()
    if packs is None:
        console.print("[yellow]No local CodeQL packs root found; using registry packs codeql/<lang>-security-extended.[/]")
    else:
        console.print(f"[green]Using CodeQL packs from:[/] {packs}")

    if workdir:
        base_dir = Path(workdir)
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir = Path(tempfile.mkdtemp(prefix="miner_"))

    if repo_name:
        repos = [_make_single_repo(org_name, repo_name)]
        console.print(f"[green]Scanning single repository:[/] {org_name}/{repo_name}")
    else:
        try:
            repos = fetch_repos(org_name)
        except Exception as e:
            console.print(f"[bold red]Error fetching repositories:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Found {len(repos)} repositories.[/]")

    results: list[RepositoryResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing repositories...", total=len(repos))

        for repo_entry in repos:
            progress.update(task, description=f"[bold]Processing {repo_entry.name}[/]")
            result = _analyze_repo(org_name, repo_entry.name, repo_entry.clone_url, repo_entry.languages_url, base_dir, packs)
            results.append(result)

            status_colors = {
                RepoStatus.ANALYZED: "green",
                RepoStatus.CLONE_FAILED: "red",
                RepoStatus.UNSUPPORTED_LANGUAGE: "yellow",
                RepoStatus.DATABASE_FAILED: "red",
                RepoStatus.ANALYSIS_FAILED: "red",
            }
            color = status_colors.get(result.status, "white")
            console.print(
                f"  [{color}]{repo_entry.name}: {result.status.value}[/]"
                + (f" - {result.error_message}" if result.error_message else "")
            )
            progress.advance(task)

    summary = _build_summary(results)
    report = OrganizationReport(
        organization=org_name,
        summary=summary,
        repositories=results,
    )

    output_path = Path(output)
    output_path.write_text(
        json.dumps(report.to_ordered_json(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[bold green]Results written to {output_path}[/]")


def _parse_target(organization: str | None, repo: str | None) -> tuple[str, str | None]:
    """Parse --organization and --repo into (org, repo_name | None)."""
    if repo and "/" in repo:
        parts = repo.split("/", 1)
        org_from_repo, repo_name = parts[0], parts[1]
        if organization and organization != org_from_repo:
            console.print(f"[bold red]Error:[/] --organization '{organization}' conflicts with --repo '{repo}'.")
            raise typer.Exit(1)
        return org_from_repo, repo_name
    if repo:
        if not organization:
            console.print("[bold red]Error:[/] --repo requires --organization (or use --repo org/repo).")
            raise typer.Exit(1)
        return organization, repo
    return organization, None


def _make_single_repo(org: str, name: str):
    """Construct a GitHubRepo-like object for a single repo without an API call."""
    from .github import GitHubRepo
    return GitHubRepo(
        name=name,
        clone_url=f"https://github.com/{org}/{name}.git",
        languages_url=f"https://api.github.com/repos/{org}/{name}/languages",
        default_branch="main",
    )


def _analyze_repo(
    organization: str,
    name: str,
    clone_url: str,
    languages_url: str,
    base_dir: Path,
    packs_root: Path | None = None,
) -> RepositoryResult:
    repo_dir = base_dir / name
    repo_url = f"https://github.com/{organization}/{name}"

    try:
        languages = fetch_languages(languages_url)
    except Exception:
        languages = []

    codeql_langs = [l.lower() for l in languages if l.lower() in SUPPORTED_CODEQL_LANGUAGES]

    try:
        clone_repo(clone_url, repo_dir)
    except Exception as e:
        return RepositoryResult(
            name=name,
            url=repo_url,
            status=RepoStatus.CLONE_FAILED,
            languages=languages,
            error_message=str(e),
        )

    if not codeql_langs:
        cleanup(repo_dir)
        return RepositoryResult(
            name=name,
            url=repo_url,
            status=RepoStatus.UNSUPPORTED_LANGUAGE,
            languages=languages,
            error_message="No CodeQL-supported languages found",
        )

    all_findings = []
    analyzed_langs = []

    for lang in codeql_langs:
        db_dir = base_dir / f"{name}-{lang}-db"
        sarif_path = base_dir / f"{name}-{lang}.sarif"

        try:
            create_database(lang, repo_dir, db_dir)
        except Exception as e:
            cleanup(repo_dir)
            if db_dir.exists():
                cleanup(db_dir)
            return RepositoryResult(
                name=name,
                url=repo_url,
                status=RepoStatus.DATABASE_FAILED,
                languages=languages,
                error_message=f"CodeQL database creation failed for {lang}: {e}",
            )

        try:
            run_analysis(db_dir, lang, sarif_path, packs_root)
            findings = parse_sarif(sarif_path)
            all_findings.extend(findings)
            analyzed_langs.append(lang)
        except Exception as e:
            cleanup(repo_dir)
            if db_dir.exists():
                cleanup(db_dir)
            if sarif_path.exists():
                sarif_path.unlink()
            return RepositoryResult(
                name=name,
                url=repo_url,
                status=RepoStatus.ANALYSIS_FAILED,
                languages=languages,
                error_message=f"CodeQL analysis failed for {lang}: {e}",
            )
        finally:
            if db_dir.exists():
                cleanup(db_dir)
            if sarif_path.exists():
                sarif_path.unlink()

    cleanup(repo_dir)

    return RepositoryResult(
        name=name,
        url=repo_url,
        status=RepoStatus.ANALYZED,
        languages=languages,
        findings=all_findings,
    )


def _build_summary(results: list[RepositoryResult]) -> AnalysisSummary:
    return AnalysisSummary(
        repositories=len(results),
        analyzed=sum(1 for r in results if r.status == RepoStatus.ANALYZED),
        clone_failed=sum(1 for r in results if r.status == RepoStatus.CLONE_FAILED),
        unsupported=sum(1 for r in results if r.status == RepoStatus.UNSUPPORTED_LANGUAGE),
        database_failed=sum(1 for r in results if r.status == RepoStatus.DATABASE_FAILED),
        analysis_failed=sum(1 for r in results if r.status == RepoStatus.ANALYSIS_FAILED),
        findings=sum(len(r.findings) for r in results),
    )
