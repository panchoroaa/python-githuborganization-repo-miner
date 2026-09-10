"""Git repository cloning operations."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from git import Repo


def clone_repo(clone_url: str, target_dir: Path) -> Repo:
    if target_dir.exists():
        cleanup(target_dir)
    return Repo.clone_from(clone_url, str(target_dir))


def cleanup(target_dir: Path, retries: int = 3) -> None:
    if not target_dir.exists():
        return
    for attempt in range(retries):
        try:
            for root, dirs, files in os.walk(str(target_dir)):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o777)
            shutil.rmtree(target_dir)
            return
        except PermissionError:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                shutil.rmtree(target_dir, ignore_errors=True)
