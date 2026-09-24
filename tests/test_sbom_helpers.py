"""Tests for the SBOM helper logic in the CLI module."""

from __future__ import annotations

from pathlib import Path

import pytest

from miner.cli import _build_sbom_result
from miner.models import SbomStatus


def _init_repo(repo_dir: Path) -> None:
    from git import Repo

    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    repo = Repo.init(str(repo_dir))
    repo.index.add(["requirements.txt"])
    repo.index.commit("initial")


def _fake_generate(components: list, raise_error: bool = False):
    """Return a generate_sbom stub that writes a CycloneDX payload to disk."""
    def fake_generate(source: Path, output: Path) -> Path:
        if raise_error:
            raise RuntimeError("syft crashed")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            '{"bomFormat": "CycloneDX", "components": ' + __import__("json").dumps(components) + "}",
            encoding="utf-8",
        )
        return output

    return fake_generate


def test_missing_clone_is_failed():
    result = _build_sbom_result(
        "org", "ghost", Path("does-not-exist"), Path("out/ghost.cdx.json"), "1.15.1"
    )
    assert result.status == SbomStatus.FAILED
    assert result.full_name == "org/ghost"
    assert "not cloned" in result.error_message
    assert result.components == 0


def test_success_with_components(monkeypatch, tmp_path: Path):
    repo_dir = tmp_path / "repo" / "clone"
    _init_repo(repo_dir)
    sbom_path = tmp_path / "out" / "repo.cdx.json"

    import miner.cli as cli

    monkeypatch.setattr(cli, "generate_sbom", _fake_generate([{"name": "flask"}]))
    result = _build_sbom_result("org", "repo", repo_dir, sbom_path, "1.15.1")

    assert result.status == SbomStatus.SUCCESS
    assert result.components == 1
    assert result.commit
    assert result.sbom_path == str(sbom_path.resolve())
    assert result.error_message is None
    assert sbom_path.exists()


def test_success_without_components(monkeypatch, tmp_path: Path):
    """A successful run with 0 components maps to NO_COMPONENTS, not FAILED."""
    repo_dir = tmp_path / "repo2" / "clone"
    _init_repo(repo_dir)
    sbom_path = tmp_path / "out" / "repo2.cdx.json"

    import miner.cli as cli

    monkeypatch.setattr(cli, "generate_sbom", _fake_generate([]))
    result = _build_sbom_result("org", "repo2", repo_dir, sbom_path, "1.15.1")

    assert result.status == SbomStatus.NO_COMPONENTS
    assert result.components == 0
    assert result.error_message is None
    assert result.sbom_path == str(sbom_path.resolve())


def test_failure_is_recorded_and_does_not_raise(monkeypatch, tmp_path: Path):
    repo_dir = tmp_path / "repo3" / "clone"
    _init_repo(repo_dir)
    sbom_path = tmp_path / "out" / "repo3.cdx.json"

    import miner.cli as cli

    monkeypatch.setattr(cli, "generate_sbom", _fake_generate([], raise_error=True))
    result = _build_sbom_result("org", "repo3", repo_dir, sbom_path, "1.15.1")

    assert result.status == SbomStatus.FAILED
    assert "SBOM generation failed" in result.error_message
    assert result.components == 0