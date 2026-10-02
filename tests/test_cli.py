"""Tests for CLI helpers (sorting and limiting repositories)."""

from __future__ import annotations

import pytest

from miner.cli import _apply_sort_limit
from miner.github import GitHubRepo


def make_repo(name: str, stars: int = 0, forks: int = 0, size: int = 0, pushed_at: str = "") -> GitHubRepo:
    return GitHubRepo(
        name=name,
        clone_url=f"https://github.com/o/{name}.git",
        languages_url=f"https://api.github.com/repos/o/{name}/languages",
        default_branch="main",
        stargazers_count=stars,
        forks_count=forks,
        size=size,
        pushed_at=pushed_at,
    )


class TestApplySortLimit:
    def test_no_options_returns_unchanged(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10)]
        assert _apply_sort_limit(repos, None, None) == repos

    def test_limit_only_takes_top_by_stars(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10), make_repo("c", stars=1)]
        result = _apply_sort_limit(repos, 2, None)
        assert [r.name for r in result] == ["b", "a"]

    def test_sort_by_stars_descending(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10), make_repo("c", stars=1)]
        result = _apply_sort_limit(repos, None, "stars")
        assert [r.name for r in result] == ["b", "a", "c"]

    def test_sort_by_name_ascending(self):
        repos = [make_repo("banana"), make_repo("apple"), make_repo("cherry")]
        result = _apply_sort_limit(repos, None, "name")
        assert [r.name for r in result] == ["apple", "banana", "cherry"]

    def test_sort_by_forks_and_limit(self):
        repos = [make_repo("a", forks=2), make_repo("b", forks=9), make_repo("c", forks=4)]
        result = _apply_sort_limit(repos, 2, "forks")
        assert [r.name for r in result] == ["b", "c"]

    def test_sort_by_pushed_at_strings(self):
        repos = [
            make_repo("old", pushed_at="2020-01-01T00:00:00Z"),
            make_repo("new", pushed_at="2025-06-01T00:00:00Z"),
        ]
        result = _apply_sort_limit(repos, None, "pushed")
        assert [r.name for r in result] == ["new", "old"]

    def test_limit_larger_than_list(self):
        repos = [make_repo("a", stars=1), make_repo("b", stars=2)]
        result = _apply_sort_limit(repos, 50, None)
        assert [r.name for r in result] == ["b", "a"]

    def test_unknown_criterion_raises(self):
        with pytest.raises(ValueError):
            _apply_sort_limit([make_repo("a")], 10, "wat")

    def test_empty_list(self):
        assert _apply_sort_limit([], 10, "stars") == []
        assert _apply_sort_limit([], None, None) == []


class TestNormalizeLanguage:
    def test_aliases_c_and_csharp(self):
        from miner.cli import _normalize_language

        assert _normalize_language("C++") == "cpp"
        assert _normalize_language("C#") == "csharp"
        assert _normalize_language("Python") == "python"
        assert _normalize_language("c") == "c"
        assert _normalize_language("Kotlin") == "kotlin"


class TestAnalyzeRepoResilience:
    """_analyze_repo should keep going when one language fails."""

    def test_analyzed_when_one_language_fails(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import Finding, RepoStatus

        def fake_langs(url):
            return ["JavaScript", "Swift"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            if lang == "swift":
                raise RuntimeError("autobuild failed (no Xcode)")
            return db_dir

        def fake_analyze(db_dir, lang, sarif_path, packs_root):
            sarif_path.write_text("{}")

        def fake_parse(sarif_path):
            return [
                Finding(
                    rule_id="js/xss",
                    severity="warning",
                    message="xss",
                    file="app.js",
                    start_line=1,
                )
            ]

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)
        monkeypatch.setattr("miner.cli.run_analysis", fake_analyze)
        monkeypatch.setattr("miner.cli.parse_sarif", fake_parse)

        result = _analyze_repo(
            "mozilla", "send", "https://github.com/mozilla/send.git",
            "https://api.github.com/repos/mozilla/send/languages", tmp_path,
        )

        assert result.status == RepoStatus.ANALYZED
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "js/xss"
        assert "swift" in (result.error_message or "")

    def test_database_failed_when_all_fail(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        def fake_langs(url):
            return ["Swift"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            raise RuntimeError("autobuild failed")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)

        result = _analyze_repo(
            "mozilla", "send", "https://github.com/mozilla/send.git",
            "https://api.github.com/repos/mozilla/send/languages", tmp_path,
        )

        assert result.status == RepoStatus.DATABASE_FAILED
        assert "swift" in (result.error_message or "")

    def test_analysis_failed_when_all_analyses_fail(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        def fake_langs(url):
            return ["JavaScript"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            return db_dir

        def fake_analyze(db_dir, lang, sarif_path, packs_root):
            raise RuntimeError("analysis crashed")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)
        monkeypatch.setattr("miner.cli.run_analysis", fake_analyze)

        result = _analyze_repo(
            "mozilla", "pdf", "https://github.com/mozilla/pdf.js.git",
            "https://api.github.com/repos/mozilla/pdf.js/languages", tmp_path,
        )

        assert result.status == RepoStatus.ANALYSIS_FAILED
        assert "javascript" in (result.error_message or "")

    def test_cpp_maps_to_codeql_language(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        tried: list[str] = []

        def fake_langs(url):
            return ["C++", "Python"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            tried.append(lang)
            db_dir.mkdir(parents=True, exist_ok=True)
            raise RuntimeError("no build system")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)

        result = _analyze_repo(
            "mozilla", "deepspeech", "https://github.com/mozilla/DeepSpeech.git",
            "https://api.github.com/repos/mozilla/DeepSpeech/languages", tmp_path,
        )

        assert result.status == RepoStatus.DATABASE_FAILED
        # GitHub's "C++" must be mapped to CodeQL's "cpp" and tried
        assert "cpp" in tried
        assert "python" in tried