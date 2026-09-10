"""CodeQL CLI interaction module."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

SUITE_LANG_DIRS = {
    "typescript": "javascript",
    "c": "cpp",
}

LANGUAGE_SUITES = {
    "python": "python-security-extended",
    "java": "java-security-extended",
    "javascript": "javascript-security-extended",
    "typescript": "javascript-security-extended",
    "csharp": "csharp-security-extended",
    "cpp": "cpp-security-extended",
    "c": "cpp-security-extended",
    "go": "go-security-extended",
    "ruby": "ruby-security-extended",
    "swift": "swift-security-extended",
}


def detect_packs_root() -> Path | None:
    env_root = os.environ.get("CODEQL_PACK_ROOT")
    if env_root and Path(env_root).exists():
        return Path(env_root)

    candidates = [
        Path.home() / "cybersec" / "codeql-repo",
        Path.home() / "codeql-queries",
        Path.cwd() / "codeql-repo",
    ]
    for candidate in candidates:
        if (candidate / "codeql-workspace.yml").exists() or (
            candidate / "python" / "ql" / "src" / "qlpack.yml"
        ).exists():
            return candidate
    return None


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr}"
        )
    return result


def create_database(
    language: str,
    source_dir: Path,
    database_dir: Path,
) -> Path:
    if database_dir.exists():
        shutil.rmtree(database_dir)
    database_dir.mkdir(parents=True, exist_ok=True)
    _run([
        "codeql", "database", "create",
        str(database_dir),
        "--language", language,
        "--source-root", str(source_dir),
        "--overwrite",
    ])
    return database_dir


def _query_spec(language: str, packs_root: Path | None) -> tuple[list[str], str]:
    suite = LANGUAGE_SUITES.get(language, f"{language}-security-extended")
    if packs_root is None:
        return [], f"codeql/{suite}"
    lang_dir = SUITE_LANG_DIRS.get(language, language)
    suite_path = (
        packs_root
        / lang_dir
        / "ql"
        / "src"
        / "codeql-suites"
        / f"{suite}.qls"
    )
    if not suite_path.exists():
        raise RuntimeError(
            f"Query suite not found at {suite_path}. "
            "Check that the CodeQL packs root is correct."
        )
    return ["--additional-packs", str(packs_root)], str(suite_path)


def run_analysis(
    database_dir: Path,
    language: str,
    output_sarif: Path,
    packs_root: Path | None = None,
) -> Path:
    additional_packs, query_spec = _query_spec(language, packs_root)
    cmd = [
        "codeql", "database", "analyze",
        str(database_dir),
        "--format=sarifv2.1.0",
        f"--output={output_sarif}",
    ]
    cmd.extend(additional_packs)
    cmd.append(query_spec)
    _run(cmd)
    return output_sarif


def get_supported_languages() -> list[str]:
    result = _run(["codeql", "resolve", "languages"], check=False)
    if result.returncode != 0:
        return []
    return [lang.strip() for lang in result.stdout.splitlines() if lang.strip()]