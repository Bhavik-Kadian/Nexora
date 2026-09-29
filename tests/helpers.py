"""Helpers shared by the tests. Test values are built at runtime; nothing key-shaped is stored."""

import os
import secrets
import shutil
import string
import subprocess
from pathlib import Path

from securegate.scanners.gitleaks import GitleaksNotFound, find_gitleaks

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = REPO_ROOT / "policy.yaml"
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"

_ALPHABET = string.ascii_letters + string.digits
_BASE32 = string.ascii_uppercase + "234567"


def random_text(length: int) -> str:
    """Fresh random letters and digits."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def random_key() -> bytes:
    """A fresh random fingerprint key."""
    return secrets.token_hex(32).encode("ascii")


def fake_acme_token() -> str:
    """A fake ACME Pay token in the real format, built at runtime."""
    return "acme_" + "live_" + random_text(32)


def fake_aws_key_id() -> str:
    """A fake AWS access key id in the real format, built at runtime."""
    return "AKIA" + "".join(secrets.choice(_BASE32) for _ in range(16))


def scan_args(target: Path, mode: str = "repo") -> list[str]:
    """Arguments for `securegate scan`, pointing at this repo's policy and Gitleaks config."""
    return [
        "scan",
        str(target),
        "--mode",
        mode,
        "--out",
        "findings.json",
        "--policy",
        str(POLICY_FILE),
        "--gitleaks-config",
        str(GITLEAKS_CONFIG),
    ]


def gitleaks_installed() -> bool:
    try:
        find_gitleaks()
    except GitleaksNotFound:
        return False
    return True


def git_installed() -> bool:
    return shutil.which("git") is not None


class GitRepo:
    """A throwaway Git repository that ignores the user's own Git config (hooks, signing)."""

    def __init__(self, path: Path, config_dir: Path) -> None:
        empty_config = config_dir / "empty.gitconfig"
        empty_config.touch()
        self.path = path
        self.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty_config),
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "author@example.com",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_COMMITTER_EMAIL": "author@example.com",
        }
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        done = subprocess.run(
            ["git", "-C", str(self.path), "-c", "commit.gpgsign=false", *args],
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def write(self, relative: str, text: str) -> Path:
        file = self.path / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8", newline="\n")
        return file

    def commit(self, message: str) -> str:
        """Commit everything and return the new commit's SHA."""
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")
