"""Every link between the project's Markdown files works: the file exists, and so does the
heading a #anchor points to (named the way GitHub names them). Web addresses are not visited."""

import re
from pathlib import Path

import pytest

from helpers import REPO_ROOT

SKIPPED_FOLDERS = {".git", ".venv", ".pytest_cache", ".ruff_cache", "node_modules", "build"}
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in REPO_ROOT.rglob("*.md")
        if not SKIPPED_FOLDERS.intersection(path.relative_to(REPO_ROOT).parts)
    )


def outside_code(path: Path) -> list[tuple[int, str]]:
    """The file's lines with their numbers, leaving out fenced code blocks."""
    lines, in_code = [], False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line):
            in_code = not in_code
        elif not in_code:
            lines.append((number, line))
    return lines


def slug(heading: str) -> str:
    """The anchor GitHub gives a heading: lower case, punctuation dropped, spaces as dashes."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    for _, line in outside_code(path):
        match = HEADING.match(line)
        if match:
            name = slug(match.group(1))
            count = seen.get(name, 0)
            found.add(name if count == 0 else f"{name}-{count}")
            seen[name] = count + 1
    return found


def broken_links(path: Path) -> list[str]:
    problems = []
    for number, line in outside_code(path):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # https:, mailto: and the like
                continue
            file_part, _, anchor = target.partition("#")
            destination = (path.parent / file_part).resolve() if file_part else path
            where = f"{path.relative_to(REPO_ROOT).as_posix()}:{number} -> {target}"
            if not destination.exists():
                problems.append(f"missing file: {where}")
            elif anchor and destination.suffix == ".md" and anchor not in anchors(destination):
                problems.append(f"missing heading: {where}")
    return problems


def test_the_project_has_markdown_pages() -> None:
    names = {path.relative_to(REPO_ROOT).as_posix() for path in markdown_files()}
    assert {"README.md", "docs/README.md"} <= names


@pytest.mark.parametrize(
    "path", markdown_files(), ids=lambda p: p.relative_to(REPO_ROOT).as_posix()
)
def test_every_link_and_anchor_works(path: Path) -> None:
    assert broken_links(path) == []


def test_slugs_follow_githubs_rules() -> None:
    assert slug("The one-time setting, done by hand on GitHub") == (
        "the-one-time-setting-done-by-hand-on-github"
    )
    assert slug("Step 1: Find") == "step-1-find"
    assert slug("`make ui` and the dashboard") == "make-ui-and-the-dashboard"
