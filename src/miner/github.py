"""GitHub API interaction module."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests


def _load_dotenv() -> None:
    env_file = Path(__file__).resolve().parents[2] / ".env"
    if not env_file.exists():
        return
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key not in os.environ:
                os.environ[key] = value


_load_dotenv()


@dataclass
class GitHubRepo:
    name: str
    clone_url: str
    languages_url: str
    default_branch: str


def _get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN environment variable is not set. "
            "Please set it to a valid GitHub personal access token."
        )
    return token


def _make_headers() -> dict[str, str]:
    return {
        "Authorization": f"token {_get_token()}",
        "Accept": "application/vnd.github+json",
    }


def fetch_repos(organization: str) -> list[GitHubRepo]:
    repos: list[GitHubRepo] = []
    url = f"https://api.github.com/orgs/{organization}/repos"
    params = {"per_page": 100, "page": 1}

    while True:
        response = requests.get(url, headers=_make_headers(), params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data:
            break
        for repo in data:
            repos.append(
                GitHubRepo(
                    name=repo["name"],
                    clone_url=repo["clone_url"],
                    languages_url=repo["languages_url"],
                    default_branch=repo.get("default_branch", "main"),
                )
            )
        if len(data) < 100:
            break
        params["page"] += 1

    return repos


def fetch_languages(languages_url: str) -> list[str]:
    response = requests.get(languages_url, headers=_make_headers(), timeout=30)
    response.raise_for_status()
    return list(response.json().keys())
