"""The demo repo generator: determinism, the Git story, ground truth, safety rules and the
catalog checks.

Convention: planted values never appear inside an assert.
"""

import csv
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from helpers import REPO_ROOT, git_installed
from securegate.cli import main
from securegate.demo.catalog import CatalogItem, load_catalog, parse_catalog
from securegate.demo.generator import DemoResult, generate
from securegate.errors import ConfigError, DemoError

needs_git = pytest.mark.skipif(not git_installed(), reason="git is not installed")


def git_out(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout


def layout(result: DemoResult) -> list[tuple[str, int, str]]:
    return [(p.file, p.line, p.kind) for p in result.planted]


# --- same seed, same repo --------------------------------------------------------------------


@needs_git
def test_same_seed_builds_the_same_repo(demo_repo: DemoResult, tmp_path: Path) -> None:
    again = generate(tmp_path / "again", seed=42)
    assert again.commits == demo_repo.commits
    assert again.ground_truth.read_bytes() == demo_repo.ground_truth.read_bytes()


@needs_git
def test_another_seed_changes_the_values_but_not_the_layout(
    demo_repo: DemoResult, tmp_path: Path
) -> None:
    other = generate(tmp_path / "other", seed=7)
    unchanged_kinds = {
        mine.kind
        for mine, theirs in zip(other.planted, demo_repo.planted, strict=True)
        if mine.raw == theirs.raw
    }
    assert layout(other) == layout(demo_repo)
    assert other.commits != demo_repo.commits
    assert unchanged_kinds <= {"placeholder", "aws_docs_example"}  # the fixed decoys


# --- the Git story ---------------------------------------------------------------------------


@needs_git
def test_every_commit_is_by_riya_demo(demo_repo: DemoResult) -> None:
    people = set(git_out(demo_repo.out, "log", "--format=%an <%ae> / %cn <%ce>").splitlines())
    assert people == {"Riya Demo <riya@example.com> / Riya Demo <riya@example.com>"}


@needs_git
def test_history_only_file_is_in_history_but_not_in_the_latest_code(
    demo_repo: DemoResult,
) -> None:
    (item,) = [p for p in demo_repo.planted if p.placement == "history-only"]
    old_content = git_out(demo_repo.out, "show", f"{item.commit}:{item.file}")
    was_committed = item.raw in old_content

    assert item.file not in git_out(demo_repo.out, "ls-files").splitlines()
    assert not (demo_repo.out / item.file).exists()
    assert was_committed


@needs_git
def test_each_ground_truth_row_points_at_its_value(demo_repo: DemoResult) -> None:
    wrong = []
    for item in demo_repo.planted:
        lines = git_out(demo_repo.out, "show", f"{item.commit}:{item.file}").split("\n")
        first_line_of_value = item.raw.split("\n")[0]
        if first_line_of_value not in lines[item.line - 1]:
            wrong.append(f"{item.kind} at {item.file}:{item.line}")
    assert wrong == []


@needs_git
def test_ground_truth_csv_lists_every_planted_line_without_values(
    demo_repo: DemoResult,
) -> None:
    with demo_repo.ground_truth.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    text = demo_repo.ground_truth.read_text(encoding="utf-8")
    kinds_with_values_in_csv = [
        p.kind for p in demo_repo.planted if any(x in text for x in p.parts)
    ]

    assert list(rows[0]) == ["file", "line", "commit", "kind", "is_secret", "expected"]
    assert [(r["file"], int(r["line"]), r["commit"], r["kind"]) for r in rows] == [
        (p.file, p.line, p.commit, p.kind) for p in demo_repo.planted
    ]
    assert kinds_with_values_in_csv == []


@needs_git
def test_working_tree_is_clean_and_local_files_stay_untracked(demo_repo: DemoResult) -> None:
    assert git_out(demo_repo.out, "status", "--porcelain", "--untracked-files=all") == ""
    assert (demo_repo.out / "ground_truth.csv").is_file()
    assert (demo_repo.out / ".securegate-demo").is_file()


@needs_git
def test_the_packaged_catalog_plants_20_lines(demo_repo: DemoResult) -> None:
    kinds = Counter(p.kind for p in demo_repo.planted)
    assert len(demo_repo.planted) == 20  # 18 items; both AWS kinds use two lines
    assert (kinds["aws_key_pair"], kinds["aws_docs_example"]) == (2, 2)
    assert sum(p.is_secret for p in demo_repo.planted) == 9


# --- safety rules ----------------------------------------------------------------------------


@needs_git
def test_a_non_empty_folder_is_refused_without_force(tmp_path: Path) -> None:
    out = tmp_path / "busy"
    out.mkdir()
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(DemoError, match="not empty"):
        generate(out, seed=1)
    assert (out / "notes.txt").read_text(encoding="utf-8") == "mine"


@needs_git
def test_force_never_empties_a_folder_the_generator_did_not_make(tmp_path: Path) -> None:
    out = tmp_path / "busy"
    out.mkdir()
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(DemoError, match="was not made by"):
        generate(out, seed=1, force=True)
    assert (out / "notes.txt").read_text(encoding="utf-8") == "mine"


@needs_git
def test_force_rebuilds_an_earlier_demo_and_touches_nothing_outside(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    neighbour = tmp_path / "keep-me.txt"
    neighbour.write_text("keep", encoding="utf-8")
    first = generate(out, seed=3)
    (out / "stray.txt").write_text("left over", encoding="utf-8")

    second = generate(out, seed=3, force=True)

    assert second.commits == first.commits
    assert not (out / "stray.txt").exists()
    assert neighbour.read_text(encoding="utf-8") == "keep"


@needs_git
def test_building_inside_a_git_repository_is_refused(make_repo) -> None:
    repo = make_repo()
    with pytest.raises(DemoError, match="inside the Git repository"):
        generate(repo.path / "demo", seed=1)
    assert not (repo.path / "demo").exists()


@pytest.mark.skipif(not (REPO_ROOT / ".git").exists(), reason="not a Git checkout")
def test_building_inside_securegate_itself_is_refused() -> None:
    target = REPO_ROOT / "securegate-demo"
    with pytest.raises(DemoError, match="inside the Git repository"):
        generate(target, seed=1)
    assert not target.exists()


# --- the demo-repo command -------------------------------------------------------------------


@needs_git
def test_demo_repo_command_prints_a_summary_and_no_values(
    demo_repo: DemoResult, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["demo-repo", "--out", str(tmp_path / "cli-demo"), "--seed", "42"])
    printed = capsys.readouterr()
    shown = printed.out + printed.err
    kinds_shown = [p.kind for p in demo_repo.planted if any(x in shown for x in p.parts)]

    assert exit_code == 0
    assert "Demo repo ready" in printed.out
    assert "9 secret lines and 11 decoy lines" in printed.out
    assert kinds_shown == []


@needs_git
def test_demo_repo_command_exits_2_when_it_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "busy"
    out.mkdir()
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    assert main(["demo-repo", "--out", str(out)]) == 2
    assert "not empty" in capsys.readouterr().err


# --- catalog checks --------------------------------------------------------------------------

GOOD_ITEM = {
    "kind": "stripe_live",
    "file": "app/pay.py",
    "placement": "current",
    "expected": "block",
}


def parse(*items: dict[str, object]) -> list[CatalogItem]:
    return parse_catalog({"items": list(items)}, source="test-catalog.yaml")


def test_the_packaged_catalog_is_valid() -> None:
    items = load_catalog()
    assert len(items) == 18
    assert sum(item.is_secret for item in items) == 8


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"kind": "stripe_lvie"}, "did you mean 'stripe_live'"),
        ({"placement": "past"}, "'placement' must be one of"),
        ({"expected": "allow"}, "'expected' must be one of"),
        ({"file": "../outside.py"}, "inside the demo repo"),
        ({"file": "/etc/hosts"}, "inside the demo repo"),
        ({"file": "C:/x.py"}, "inside the demo repo"),
        ({"file": "a\\b.py"}, "inside the demo repo"),
        ({"file": ".git/config"}, "inside the demo repo"),
        ({"file": "ground_truth.csv"}, "inside the demo repo"),
        ({"name": "not a name"}, "variable name"),
        ({"variant": "changeme"}, "only applies to kind: placeholder"),
        ({"kind": "private_key_block", "file": ".env"}, "cannot go in .env"),
        ({"kind": "minified_js", "file": "app/x.py"}, "cannot go in app/x.py"),
        ({"colour": "red"}, "unknown key 'colour'"),
        ({"file": "requirements.txt"}, "no place for planted lines"),
    ],
)
def test_bad_items_are_refused_with_a_clear_message(change: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        parse({**GOOD_ITEM, **change})


def test_unknown_placeholder_variant_gets_a_suggestion() -> None:
    with pytest.raises(ConfigError, match=re.escape("did you mean 'changeme'")):
        parse({**GOOD_ITEM, "kind": "placeholder", "variant": "chageme", "expected": "ignore"})


def test_history_only_item_needs_a_file_of_its_own() -> None:
    with pytest.raises(ConfigError, match="needs a file of its own"):
        parse({**GOOD_ITEM, "placement": "history-only"}, {**GOOD_ITEM, "kind": "github_pat"})


def test_history_only_item_cannot_use_an_app_file() -> None:
    with pytest.raises(ConfigError, match="needs a file of its own"):
        parse({**GOOD_ITEM, "file": "config/settings.py", "placement": "history-only"})


@pytest.mark.parametrize(
    ("data", "message"),
    [(None, "expected an 'items:' list"), ({"items": []}, "at least one item")],
)
def test_empty_catalogs_are_refused(data: object, message: str) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        parse_catalog(data)
