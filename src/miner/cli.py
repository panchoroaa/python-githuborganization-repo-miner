"""CLI interface using Typer."""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .codeql import create_database, detect_packs_root, fetch_packs_root, run_analysis
from .github import fetch_languages, fetch_repos
from .git_ops import cleanup, clone_repo
from .models import (
    AnalysisSummary,
    OrganizationReport,
    RepoStatus,
    RepositoryResult,
    SbomReport,
    SbomResult,
    SbomStatus,
    SbomSummary,
)
from .sarif import parse_sarif
from .syft import count_components, generate_sbom, get_repo_commit, get_syft_version

app = typer.Typer()
console = Console()

SUPPORTED_CODEQL_LANGUAGES = {
    "python", "java", "javascript", "typescript",
    "csharp", "cpp", "c", "go", "ruby", "swift", "rust",
}

# GitHub reports some languages with different names than CodeQL uses.
LANGUAGE_NAME_ALIASES = {
    "c++": "cpp",
    "c#": "csharp",
}


def _normalize_language(language: str) -> str:
    """Map a GitHub API language name to a CodeQL language id (lowercase)."""
    return LANGUAGE_NAME_ALIASES.get(language.lower(), language.lower())


def _truncate(message: str, limit: int = 160) -> str:
    """Collapse whitespace and truncate long messages for compact reports."""
    message = " ".join(message.split())
    if len(message) <= limit:
        return message
    return message[: limit - 3] + "..."

DEFAULT_SORT_BY = "stars"

SORT_CRITERIA = {
    "stars": "stargazers_count",
    "forks": "forks_count",
    "issues": "open_issues_count",
    "size": "size",
    "pushed": "pushed_at",
    "updated": "updated_at",
    "created": "created_at",
    "name": "name",
}


def _apply_sort_limit(repos, limit: int | None, sort_by: str | None):
    """Sort repositories by a criterion and optionally truncate to ``limit``.

    Sorting is descending ("top N"). ``name`` is the exception and sorts
    ascending (A→Z). When only ``--limit`` is given, defaults to sorting by
    stars. Raises ``ValueError`` for an unknown criterion.
    """
    if limit is None and sort_by is None:
        return repos

    criterion = sort_by or DEFAULT_SORT_BY
    field = SORT_CRITERIA.get(criterion)
    if field is None:
        raise ValueError(
            f"Unknown --sort-by criterion '{criterion}'. "
            f"Use one of: {', '.join(sorted(SORT_CRITERIA))}."
        )

    ordered = sorted(repos, key=lambda r: getattr(r, field), reverse=field != "name")
    if limit is not None:
        return ordered[:limit]
    return ordered


@app.command()
def scan(
    organization: str = typer.Option(None, "--organization", "-o", help="GitHub organization name"),
    repo: str = typer.Option(None, "--repo", "-r", help="Single repository to scan (e.g. OWASP/NodeGoat or just NodeGoat with -o)"),
    output: str = typer.Option("results.json", "--output", "-O", help="Output JSON file path"),
    workdir: str = typer.Option(None, "--workdir", "-w", help="Working directory for clones and databases"),
    packs_root: str = typer.Option(None, "--packs-root", "-p", help="Path to CodeQL query packs (codeql-repo). Detected automatically if omitted."),
    sbom_dir: str = typer.Option("sboms", "--sbom-dir", help="Output directory for SBOM (CycloneDX JSON) files"),
    fetch_packs: bool = typer.Option(
        True,
        "--fetch-packs/--no-fetch-packs",
        help="Clone github/codeql query packs automatically when no local packs are found",
    ),
    limit: int = typer.Option(None, "--limit", "-n", min=1, help="Process at most this many repositories (e.g. --limit 30 for the top 30)"),
    sort_by: str = typer.Option(None, "--sort-by", help="Criterion to pick repositories: stars, forks, issues, size, pushed, updated, created, name (e.g. --limit 30 --sort-by stars)"),
) -> None:
    """Scan a GitHub organization's repositories (or a single repo) for vulnerabilities using CodeQL."""

    if not organization and not repo:
        console.print("[bold red]Error:[/] Provide --organization and/or --repo.")
        raise typer.Exit(1)

    org_name, repo_name = _parse_target(organization, repo)

    packs = Path(packs_root) if packs_root else detect_packs_root()

    if packs is None and not packs_root and fetch_packs:
        console.print("[cyan]No local CodeQL packs found; cloning github/codeql (shallow clone, may take a while)...[/]")
        try:
            packs = fetch_packs_root()
            console.print(f"[green]CodeQL packs ready at:[/] {packs}")
        except Exception as e:
            console.print(f"[bold red]Could not fetch CodeQL packs:[/] {e}")
            packs = None

    if packs is None:
        console.print("[yellow]No local CodeQL packs root found; using registry packs codeql/<lang>-security-extended.[/]")
    else:
        console.print(f"[green]Using CodeQL packs from:[/] {packs}")

    syft_version = _syft_available()
    if syft_version is None:
        console.print("[yellow]Syft not found in PATH; SBOM generation will be skipped. Install Syft to enable SBOMs (see README.md).[/]")
        sbom_dir_path: Path | None = None
    else:
        sbom_dir_path = Path(sbom_dir)
        sbom_dir_path.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]SBOMs will be written to:[/] {sbom_dir_path}")

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
        if limit is not None or sort_by:
            try:
                repos = _apply_sort_limit(repos, limit, sort_by)
            except ValueError as e:
                console.print(f"[bold red]Error:[/] {e}")
                raise typer.Exit(1)
            criterion = sort_by or DEFAULT_SORT_BY
            suffix = f", max {limit}" if limit is not None else ""
            console.print(
                f"[green]Processing {len(repos)} repositories[/] "
                f"(top by '{criterion}'{suffix})."
            )

    results: list[RepositoryResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing repositories...", total=len(repos))

        for repo_entry in repos:
            progress.update(task, description=f"[bold]Processing {repo_entry.name}[/]")
            result = _analyze_repo(
                org_name, repo_entry.name, repo_entry.clone_url, repo_entry.languages_url,
                base_dir, packs, sbom_dir_path, syft_version or "",
                keep_clones=bool(workdir),
            )
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


@app.command()
def sbom(
    organization: str = typer.Option(None, "--organization", "-o", help="GitHub organization name"),
    repo: str = typer.Option(None, "--repo", "-r", help="Single repository (e.g. OWASP/NodeGoat or just NodeGoat with -o)"),
    workdir: str = typer.Option("repos", "--workdir", "-w", help="Directory containing already-cloned repositories"),
    output_dir: str = typer.Option("sbom-output", "--output-dir", "-O", help="Output directory for SBOM files and report"),
    limit: int = typer.Option(None, "--limit", "-n", min=1, help="Process at most this many repositories (e.g. --limit 30 for the top 30)"),
    sort_by: str = typer.Option(None, "--sort-by", help="Criterion to pick repositories: stars, forks, issues, size, pushed, updated, created, name (e.g. --limit 30 --sort-by stars)"),
) -> None:
    """Generate CycloneDX JSON SBOMs for an organization's cloned repositories using Syft (no CodeQL)."""

    if not organization and not repo:
        console.print("[bold red]Error:[/] Provide --organization and/or --repo.")
        raise typer.Exit(1)

    org_name, repo_name = _parse_target(organization, repo)

    syft_version = _syft_available()
    if syft_version is None:
        console.print("[bold red]Error:[/] Syft not found in PATH. Install Syft first (see README.md).")
        raise typer.Exit(1)

    base_dir = Path(workdir)
    if not base_dir.exists():
        console.print(
            f"[bold red]Error:[/] Workdir '{base_dir}' does not exist. "
            "Clone repositories first, e.g. with 'miner scan --workdir <dir>'."
        )
        raise typer.Exit(1)

    if repo_name:
        repos = [_make_single_repo(org_name, repo_name)]
        console.print(f"[green]Generating SBOM for repository:[/] {org_name}/{repo_name}")
    else:
        try:
            repos = fetch_repos(org_name)
        except Exception as e:
            console.print(f"[bold red]Error fetching repositories:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Found {len(repos)} repositories.[/]")
        if limit is not None or sort_by:
            try:
                repos = _apply_sort_limit(repos, limit, sort_by)
            except ValueError as e:
                console.print(f"[bold red]Error:[/] {e}")
                raise typer.Exit(1)
            criterion = sort_by or DEFAULT_SORT_BY
            suffix = f", max {limit}" if limit is not None else ""
            console.print(
                f"[green]Processing {len(repos)} repositories[/] "
                f"(top by '{criterion}'{suffix})."
            )

    out_dir = Path(output_dir)
    sboms_dir = out_dir / "sboms"
    sboms_dir.mkdir(parents=True, exist_ok=True)

    results: list[SbomResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating SBOMs...", total=len(repos))

        for repo_entry in repos:
            progress.update(task, description=f"[bold]Processing {repo_entry.name}[/]")
            repo_dir = base_dir / repo_entry.name
            result = _build_sbom_result(
                org_name,
                repo_entry.name,
                repo_dir,
                sboms_dir / f"{repo_entry.name}.cdx.json",
                syft_version,
            )
            results.append(result)

            status_colors = {
                SbomStatus.SUCCESS: "green",
                SbomStatus.NO_COMPONENTS: "yellow",
                SbomStatus.FAILED: "red",
            }
            color = status_colors.get(result.status, "white")
            console.print(
                f"  [{color}]{result.full_name}: {result.status.value}[/]"
                + (f" - {result.error_message}" if result.error_message else "")
            )
            progress.advance(task)

    summary = SbomSummary(
        repositories=len(results),
        success=sum(1 for r in results if r.status == SbomStatus.SUCCESS),
        no_components=sum(1 for r in results if r.status == SbomStatus.NO_COMPONENTS),
        failed=sum(1 for r in results if r.status == SbomStatus.FAILED),
        components=sum(r.components for r in results),
    )
    report = SbomReport(
        organization=org_name,
        generated_at=datetime.now(timezone.utc),
        syft_version=syft_version,
        summary=summary,
        repositories=results,
    )

    report_path = out_dir / "sbom-report.json"
    report_path.write_text(
        json.dumps(report.to_ordered_json(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[bold green]SBOM report written to {report_path}[/]")


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
    sbom_dir: Path | None = None,
    syft_version: str = "",
    keep_clones: bool = False,
) -> RepositoryResult:
    repo_dir = base_dir / name
    repo_url = f"https://github.com/{organization}/{name}"

    try:
        languages = fetch_languages(languages_url)
    except Exception:
        languages = []

    codeql_langs: list[str] = []
    for l in languages:
        norm = _normalize_language(l)
        if norm in SUPPORTED_CODEQL_LANGUAGES and norm not in codeql_langs:
            codeql_langs.append(norm)

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

    sbom_result: SbomResult | None = None
    if sbom_dir is not None:
        sbom_result = _build_sbom_result(
            organization, name, repo_dir, sbom_dir / f"{name}.cdx.json", syft_version
        )

    if not codeql_langs:
        if not keep_clones:
            cleanup(repo_dir)
        return RepositoryResult(
            name=name,
            url=repo_url,
            status=RepoStatus.UNSUPPORTED_LANGUAGE,
            languages=languages,
            error_message="No CodeQL-supported languages found",
            sbom=sbom_result,
        )

    all_findings = []
    analyzed_langs: list[str] = []
    db_failures: list[str] = []
    analysis_failures: list[str] = []

    for lang in codeql_langs:
        db_dir = base_dir / f"{name}-{lang}-db"
        sarif_path = base_dir / f"{name}-{lang}.sarif"

        try:
            create_database(lang, repo_dir, db_dir)
        except Exception as e:
            db_failures.append(f"{lang}: {_truncate(str(e))}")
            if db_dir.exists():
                cleanup(db_dir)
            continue

        try:
            run_analysis(db_dir, lang, sarif_path, packs_root)
            findings = parse_sarif(sarif_path)
            all_findings.extend(findings)
            analyzed_langs.append(lang)
        except Exception as e:
            analysis_failures.append(f"{lang}: {_truncate(str(e), 200)}")
        finally:
            if db_dir.exists():
                cleanup(db_dir)
            if sarif_path.exists():
                sarif_path.unlink()

    if not analyzed_langs:
        if not keep_clones:
            cleanup(repo_dir)
        if analysis_failures:
            status = RepoStatus.ANALYSIS_FAILED
            message = "CodeQL analysis failed: " + "; ".join(analysis_failures)
        else:
            status = RepoStatus.DATABASE_FAILED
            message = "CodeQL database creation failed: " + "; ".join(db_failures)
        return RepositoryResult(
            name=name,
            url=repo_url,
            status=status,
            languages=languages,
            error_message=message,
            sbom=sbom_result,
        )

    if not keep_clones:
        cleanup(repo_dir)

    failures = db_failures + analysis_failures
    return RepositoryResult(
        name=name,
        url=repo_url,
        status=RepoStatus.ANALYZED,
        languages=languages,
        findings=all_findings,
        error_message=("Skipped languages: " + "; ".join(failures)) if failures else None,
        sbom=sbom_result,
    )


def _syft_available() -> str | None:
    """Return the installed Syft version string, or None if Syft is not usable."""
    if shutil.which("syft") is None:
        return None
    try:
        return get_syft_version()
    except Exception as e:
        console.print(f"[yellow]Warning: could not determine Syft version: {e}[/]")
        return None


def _build_sbom_result(
    organization: str,
    name: str,
    repo_dir: Path,
    sbom_path: Path,
    syft_version: str = "",
) -> SbomResult:
    """Generate an SBOM for a local clone and return the SbomResult for it.

    Distinguishes between a failed run (FAILED), a successful run with no
    identified components (NO_COMPONENTS) and a successful run with components
    (SUCCESS). Never raises: failures are recorded in the result.
    """
    full_name = f"{organization}/{name}"
    generated_at = datetime.now(timezone.utc)

    def _failed(message: str, commit: str | None = None) -> SbomResult:
        return SbomResult(
            full_name=full_name,
            commit=commit,
            generated_at=generated_at,
            syft_version=syft_version,
            status=SbomStatus.FAILED,
            error_message=message,
        )

    if not repo_dir.exists():
        return _failed(f"Repository not cloned at {repo_dir}")

    try:
        commit = get_repo_commit(repo_dir)
    except Exception as e:
        commit = None

    try:
        generate_sbom(repo_dir, sbom_path)
        components = count_components(sbom_path)
    except Exception as e:
        return _failed(f"SBOM generation failed: {e}", commit)

    return SbomResult(
        full_name=full_name,
        commit=commit,
        generated_at=generated_at,
        syft_version=syft_version,
        status=SbomStatus.SUCCESS if components > 0 else SbomStatus.NO_COMPONENTS,
        components=components,
        sbom_path=str(sbom_path.resolve()),
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
