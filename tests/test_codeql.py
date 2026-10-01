"""Tests for the CodeQL CLI wrapper module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from miner.codeql import (
    DEFAULT_PACKS_URL,
    LANGUAGE_SUITES,
    _is_packs_root,
    _query_spec,
    detect_packs_root,
    fetch_packs_root,
)

RUST_SUITE = "rust-security-extended.qls"


def _make_packs_root(root: Path) -> None:
    (root / "python" / "ql" / "src").mkdir(parents=True)
    (root / "python" / "ql" / "src" / "qlpack.yml").write_text("name: codeql/python-queries\n")
    (root / "codeql-workspace.yml").write_text("provide: []\n")


def _make_suite(root: Path, lang: str, suite: str) -> None:
    suites = root / lang / "ql" / "src" / "codeql-suites"
    suites.mkdir(parents=True)
    (suites / suite).write_text("")


class TestLanguageSuites:
    def test_rust_is_mapped_to_security_extended(self):
        assert LANGUAGE_SUITES["rust"] == "rust-security-extended"

    def test_supported_languages_have_suites(self):
        for lang in ("python", "javascript", "java", "go", "ruby", "swift", "rust"):
            assert lang in LANGUAGE_SUITES

    def test_rust_lang_dir_is_rust(self):
        spec = _query_spec("rust", None)
        # Registry-based spec: no additional packs, "codeql/<suite>" reference.
        assert spec == ([], "codeql/rust-security-extended")

    def test_query_spec_uses_local_rust_suite(self, tmp_path: Path):
        root = tmp_path / "codeql-repo"
        _make_packs_root(root)
        _make_suite(root, "rust", RUST_SUITE)

        additional, spec = _query_spec("rust", root)
        assert additional == ["--additional-packs", str(root)]
        assert spec == str(root / "rust" / "ql" / "src" / "codeql-suites" / RUST_SUITE)


class TestIsPacksRootAndDetect:
    def test_detects_valid_root(self, tmp_path: Path):
        root = tmp_path / "codeql-repo"
        _make_packs_root(root)
        assert _is_packs_root(root)

    def test_rejects_invalid_root(self, tmp_path: Path):
        root = tmp_path / "not-codeql"
        root.mkdir()
        (root / "README.md").write_text("hi")
        assert not _is_packs_root(root)

    def test_detect_uses_env_var(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "from-env"
        _make_packs_root(root)
        monkeypatch.setenv("CODEQL_PACK_ROOT", str(root))
        assert detect_packs_root() == root

    def test_detect_ignores_env_var_when_missing(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CODEQL_PACK_ROOT", str(tmp_path / "missing"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        assert detect_packs_root() is None


class TestFetchPacksRoot:
    def test_returns_existing_valid_root(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "codeql-repo"
        _make_packs_root(root)
        ran: list[list[str]] = []

        def fake_run(cmd: list[str], check: bool = True) -> MagicMock:
            ran.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("miner.codeql._run", fake_run)
        assert fetch_packs_root(root) == root
        assert ran == []

    def test_clones_when_missing(self, tmp_path: Path, monkeypatch):
        dest = tmp_path / "codeql-repo"
        run_cmds: list[list[str]] = []

        def fake_run(cmd: list[str], check: bool = True) -> MagicMock:
            run_cmds.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("miner.codeql._run", fake_run)
        result = fetch_packs_root(dest)

        assert result == dest
        assert dest.exists()
        assert len(run_cmds) == 1
        cmd = run_cmds[0]
        assert cmd[0] == "git"
        assert cmd[1] == "clone"
        assert "--depth" in cmd and "1" in cmd
        assert DEFAULT_PACKS_URL in cmd
        assert str(dest) in cmd

    def test_default_destination_is_cybersec(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("miner.codeql.Path.home", lambda: tmp_path)
        dest = tmp_path / "cybersec" / "codeql-repo"

        def fake_run(cmd: list[str], check: bool = True) -> MagicMock:
            return MagicMock(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("miner.codeql._run", fake_run)
        assert fetch_packs_root() == dest

    def test_raises_when_destination_exists_but_invalid(self, tmp_path: Path):
        dest = tmp_path / "codeql-repo"
        dest.mkdir()
        (dest / "random-file.txt").write_text("hi")
        with pytest.raises(RuntimeError):
            fetch_packs_root(dest)

    def test_raises_when_clone_fails(self, tmp_path: Path, monkeypatch):
        dest = tmp_path / "codeql-repo"

        def fake_run(cmd: list[str], check: bool = True) -> MagicMock:
            result = MagicMock(returncode=1, stdout="", stderr="fatal: could not clone")
            if check:
                raise RuntimeError(result.stderr)
            return result

        monkeypatch.setattr("miner.codeql._run", fake_run)
        with pytest.raises(RuntimeError):
            fetch_packs_root(dest)