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
    organization: str = typer.Option(..., "--organization", "-o", help="GitHub organization name"),
    output: str = typer.Option("results.json", "--output", "-O", help="Output JSON file path"),
    workdir: str = typer.Option(None, "--workdir", "-w", help="Working directory for clones and databases"),
    packs_root: str = typer.Option(None, "--packs-root", "-p", help="Path to CodeQL query packs (codeql-repo). Detected automatically if omitted."),
) -> None:
    """Scan a GitHub organization's repositories for vulnerabilities using CodeQL."""

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

    try:
        repos = fetch_repos(organization)
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

        for repo in repos:
            progress.update(task, description=f"[bold]Processing {repo.name}[/]")
            result = _analyze_repo(organization, repo.name, repo.clone_url, repo.languages_url, base_dir, packs)
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
                f"  [{color}]{repo.name}: {result.status.value}[/]"
                + (f" - {result.error_message}" if result.error_message else "")
            )
            progress.advance(task)

    summary = _build_summary(results)
    report = OrganizationReport(
        organization=organization,
        summary=summary,
        repositories=results,
    )

    output_path = Path(output)
    output_path.write_text(
        json.dumps(report.to_ordered_json(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[bold green]Results written to {output_path}[/]")


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
