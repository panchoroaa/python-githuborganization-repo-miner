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