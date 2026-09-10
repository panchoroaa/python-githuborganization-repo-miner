"""Tests for GitHub API module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from miner.github import GitHubRepo, fetch_languages, fetch_repos


class TestFetchRepos:
    @patch("miner.github.requests.get")
    def test_single_page(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name": "repo1", "clone_url": "https://github.com/org/repo1.git",
             "languages_url": "https://api.github.com/repos/org/repo1/languages",
             "default_branch": "main"},
            {"name": "repo2", "clone_url": "https://github.com/org/repo2.git",
             "languages_url": "https://api.github.com/repos/org/repo2/languages",
             "default_branch": "main"},
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("test-org")

        assert len(repos) == 2
        assert repos[0].name == "repo1"
        assert repos[1].name == "repo2"
        assert mock_get.call_count == 1

    @patch("miner.github.requests.get")
    def test_pagination(self, mock_get):
        page1_response = MagicMock()
        page1_response.json.return_value = [
            {"name": f"repo{i}", "clone_url": f"https://github.com/org/repo{i}.git",
             "languages_url": f"https://api.github.com/repos/org/repo{i}/languages",
             "default_branch": "main"}
            for i in range(100)
        ]
        page1_response.raise_for_status = MagicMock()

        page2_response = MagicMock()
        page2_response.json.return_value = [
            {"name": "repo100", "clone_url": "https://github.com/org/repo100.git",
             "languages_url": "https://api.github.com/repos/org/repo100/languages",
             "default_branch": "main"},
        ]
        page2_response.raise_for_status = MagicMock()

        mock_get.side_effect = [page1_response, page2_response]

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("test-org")

        assert len(repos) == 101
        assert mock_get.call_count == 2

    @patch("miner.github.requests.get")
    def test_empty_org(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("empty-org")

        assert repos == []


class TestFetchLanguages:
    @patch("miner.github._get_token", return_value="fake-token")
    @patch("miner.github.requests.get")
    def test_fetch_languages(self, mock_get, mock_token):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Python": 1000, "JavaScript": 500}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        langs = fetch_languages("https://api.github.com/repos/org/repo/languages")
        assert langs == ["Python", "JavaScript"]


class TestGitHubRepo:
    def test_dataclass(self):
        repo = GitHubRepo(
            name="test",
            clone_url="https://github.com/org/test.git",
            languages_url="https://api.github.com/repos/org/test/languages",
            default_branch="main",
        )
        assert repo.name == "test"
        assert repo.default_branch == "main"
