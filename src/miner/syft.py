"""Syft CLI interaction module for SBOM generation."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from git import Repo


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr}"
        )
    return result


def get_syft_version() -> str:
    """Return the installed Syft version string (e.g. '1.15.1')."""
    result = _run(["syft", "version"])
    match = re.search(r"(?im)^\s*Version:\s*(\S+)", result.stdout)
    if match:
        return match.group(1)

    # Fallback: some builds only expose version info through JSON output.
    try:
        result = _run(["syft", "version", "--format", "json"])
        data = json.loads(result.stdout)
        version = data.get("version", "")
        if version:
            return str(version)
    except Exception:
        pass

    first_line = next(
        (line.strip() for line in result.stdout.splitlines() if line.strip()),
        "",
    )
    return first_line


def generate_sbom(source_dir: Path, output_path: Path) -> Path:
    """Run Syft over a local directory and write a CycloneDX JSON SBOM file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run([
        "syft", "packages",
        str(source_dir),
        "-o", f"cyclonedx-json={output_path}",
    ])
    return output_path


def count_components(sbom_path: Path) -> int:
    """Return the number of components listed in a CycloneDX JSON SBOM."""
    with open(sbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return len(data.get("components", []))


def get_repo_commit(repo_dir: Path) -> str:
    """Return the hex SHA of the HEAD commit of a local clone."""
    return Repo(str(repo_dir)).head.commit.hexsha