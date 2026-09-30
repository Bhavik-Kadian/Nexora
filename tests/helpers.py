"""Helpers shared by the tests. Test values are built at runtime; nothing key-shaped is stored."""

import os
import secrets
import shutil
import string
import subprocess
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path

from securegate.demo.generator import PlantedLine
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


def leaked(planted: Sequence[PlantedLine], text: str) -> list[str]:
    """Where a planted value, or the hidden middle of a long one, shows up in `text`.
    Names only the kind and location, never the value."""
    found = []
    for item in planted:
        for part in item.parts:
            if part in text or (len(part) >= 16 and part[4:-4] in text):
                found.append(f"{item.kind} at {item.file}:{item.line}")
                break
    return found


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


class Page(HTMLParser):
    """The tags (with attributes) and visible text of an HTML page, for structure checks."""

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self._text: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self._text.append(data)

    @property
    def text(self) -> str:
        return " ".join(" ".join(self._text).split())

    def all(self, tag: str) -> list[dict[str, str | None]]:
        return [attrs for name, attrs in self.tags if name == tag]


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
