"""Tests for the Syft CLI wrapper module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from miner.syft import (
    count_components,
    generate_sbom,
    get_repo_commit,
    get_syft_version,
)

SAMPLE_VERSION_OUTPUT = """Application:     syft
Version:         1.15.1
BuildDate:       2025-01-01T00:00:00Z
GitCommit:       deadbeef
Platform:        windows/amd64
"""


def _mock_process(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


class TestGetSyftVersion:
    @patch("miner.syft.subprocess.run")
    def test_parses_version_line(self, mock_run):
        mock_run.return_value = _mock_process(stdout=SAMPLE_VERSION_OUTPUT)
        assert get_syft_version() == "1.15.1"

    @patch("miner.syft.subprocess.run")
    def test_falls_back_to_json(self, mock_run):
        mock_run.side_effect = [
            _mock_process(stdout="no structured version here"),
            _mock_process(stdout=json.dumps({"version": "0.99.0"})),
        ]
        assert get_syft_version() == "0.99.0"

    @patch("miner.syft.subprocess.run")
    def test_raises_on_failure(self, mock_run):
        mock_run.return_value = _mock_process(returncode=1, stderr="syft: not found")
        with pytest.raises(RuntimeError):
            get_syft_version()


class TestGenerateSbom:
    @patch("miner.syft.subprocess.run")
    def test_builds_cyclonedx_json_command(self, mock_run, tmp_path: Path):
        mock_run.return_value = _mock_process()
        source = tmp_path / "clone"
        source.mkdir()
        output = tmp_path / "out" / "repo.cdx.json"

        result = generate_sbom(source, output)

        assert result == output
        # Parent directory must be created even before syft runs.
        assert output.parent.exists()

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "syft"
        assert cmd[1] == "packages"
        assert str(source) in cmd
        assert f"cyclonedx-json={output}" in cmd

    @patch("miner.syft.subprocess.run")
    def test_raises_on_nonzero_exit(self, mock_run, tmp_path: Path):
        mock_run.return_value = _mock_process(returncode=1, stderr="cataloger error")
        with pytest.raises(RuntimeError):
            generate_sbom(tmp_path, tmp_path / "sbom.json")


class TestCountComponents:
    def _write_sbom(self, tmp_path: Path, payload: dict) -> Path:
        path = tmp_path / "sbom.cdx.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_counts_components(self, tmp_path: Path):
        path = self._write_sbom(tmp_path, {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "library", "name": "flask"},
                {"type": "library", "name": "requests"},
            ],
        })
        assert count_components(path) == 2

    def test_no_components_key_means_zero(self, tmp_path: Path):
        path = self._write_sbom(tmp_path, {"bomFormat": "CycloneDX"})
        assert count_components(path) == 0

    def test_empty_components_is_zero(self, tmp_path: Path):
        """Zero components is a valid, successful SBOM, not a failure."""
        path = self._write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": []})
        assert count_components(path) == 0

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            count_components(tmp_path / "missing.cdx.json")


class TestGetRepoCommit:
    def test_returns_head_commit(self, tmp_path: Path):
        from git import Repo

        repo_dir = tmp_path / "clone"
        repo_dir.mkdir()
        (repo_dir / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        repo = Repo.init(str(repo_dir))
        repo.index.add(["requirements.txt"])
        repo.index.commit("initial")

        commit = get_repo_commit(repo_dir)
        assert commit == repo.head.commit.hexsha
        assert len(commit) == 40

    def test_raises_without_repo(self, tmp_path: Path):
        with pytest.raises(Exception):
            get_repo_commit(tmp_path / "not-a-repo")
