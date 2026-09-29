"""Build the demo repository: the fake DemoPay app with planted secrets and decoys, a real Git
history, and ground_truth.csv, which lists every planted line and what SecureGate should decide.

Safety rules:
  * the output folder must be outside every Git repository (SecureGate's own included);
  * a non-empty folder is refused unless --force is given;
  * --force only empties a folder that an earlier run marked with .securegate-demo, and it never
    deletes anything outside that folder.
Same seed = same repo: values come from random.Random(seed), and Git runs with a fixed author,
fixed dates and none of the user's own Git settings (hooks, signing, line-ending conversion).
"""

import csv
import os
import random
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

import jinja2

from securegate.demo import fakes
from securegate.demo.app import (
    APP_NAME,
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    BASE_FILES,
    GENERIC_TEMPLATES,
    STORY,
)
from securegate.demo.catalog import CatalogItem, load_catalog
from securegate.errors import DemoError
from securegate.programs import find_program

MARKER_FILE = ".securegate-demo"
GROUND_TRUTH_FILE = "ground_truth.csv"
GROUND_TRUTH_COLUMNS = ("file", "line", "commit", "kind", "is_secret", "expected")
FIRST_COMMIT_DATE = datetime(2025, 6, 2, 9, 0, tzinfo=UTC)
PLANT_MARKER = "@@PLANT_HERE@@"


@dataclass(frozen=True)
class PlantedLine:
    """One planted value: a row of ground_truth.csv, plus the value itself for tests."""

    file: str
    line: int
    commit: str
    kind: str
    is_secret: bool
    expected: str
    placement: str
    raw: str = field(repr=False)  # the fake value; never print it
    parts: tuple[str, ...] = field(repr=False)  # text that must never appear in any output


@dataclass(frozen=True)
class DemoResult:
    out: Path
    seed: int
    commits: tuple[str, ...]
    planted: tuple[PlantedLine, ...]

    @property
    def ground_truth(self) -> Path:
        return self.out / GROUND_TRUTH_FILE


@dataclass(frozen=True)
class _RenderedFile:
    text: str
    planted: tuple[tuple[CatalogItem, fakes.Value, int], ...]  # item, value, line number
    history_only: bool


def generate(
    out: Path, *, seed: int, force: bool = False, catalog: Sequence[CatalogItem] | None = None
) -> DemoResult:
    """Build the demo repo in `out` and return what was planted where."""
    items = list(catalog) if catalog is not None else load_catalog()
    git_program = find_program("git")
    if git_program is None:
        raise DemoError("Git was not found on PATH; the demo repo needs it")
    out = _prepare_output(out, force)
    files = _render_files(items, random.Random(seed))  # noqa: S311 - reproducible fake data
    with tempfile.TemporaryDirectory(prefix="securegate-demo-git-") as scratch:
        git = _Git(git_program, out, Path(scratch))
        git.init()
        commits, commit_of = _write_history(out, files, git)
    planted = _planted_lines(files, commits, commit_of)
    _write_ground_truth(out / GROUND_TRUTH_FILE, planted)
    return DemoResult(out=out, seed=seed, commits=tuple(commits), planted=tuple(planted))


# --- the output folder -----------------------------------------------------------------------


def _prepare_output(out: Path, force: bool) -> Path:
    out = out.expanduser().resolve()
    if out.parent == out:
        raise DemoError(f"refusing to use {out} as the demo folder")
    repo = _enclosing_git_repo(out)
    if repo is not None:
        raise DemoError(
            f"{out} is inside the Git repository {repo}. Demo repos must be built outside every "
            "repository, for example in ../securegate-demo next to SecureGate."
        )
    if out.exists() and not out.is_dir():
        raise DemoError(f"{out} exists and is not a folder")
    if out.exists() and any(out.iterdir()):
        if not force:
            raise DemoError(
                f"{out} is not empty. Use --force to rebuild an earlier demo repo there, "
                "or choose an empty folder."
            )
        if not (out / MARKER_FILE).is_file():
            raise DemoError(
                f"{out} is not empty and was not made by `securegate demo-repo` (it has no "
                f"{MARKER_FILE} file), so --force will not delete anything in it. "
                "Choose another folder."
            )
        _empty_folder(out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / MARKER_FILE).write_text(
            "Made by `securegate demo-repo`. It may be emptied and rebuilt with --force.\n",
            encoding="utf-8",
        )
    except OSError as err:
        raise DemoError(f"cannot create the demo folder {out}: {err}") from None
    return out


def _enclosing_git_repo(folder: Path) -> Path | None:
    """The Git working tree that `folder` would be inside of, if any."""
    for parent in folder.parents:
        if (parent / ".git").exists():
            return parent
    return None


def _empty_folder(folder: Path) -> None:
    """Delete everything inside `folder`: never the folder itself, never anything outside it."""
    for child in folder.iterdir():
        try:
            if child.is_symlink() or child.is_junction():
                _remove_link(child)  # remove the link only, never what it points to
            elif child.is_dir():
                shutil.rmtree(child, onexc=_make_writable_and_retry)
            else:
                _make_writable_and_retry(os.unlink, str(child), None)
        except OSError as err:
            raise DemoError(f"could not delete {child}: {err}") from None


def _remove_link(link: Path) -> None:
    try:
        link.unlink()
    except OSError:
        os.rmdir(link)  # directory links on Windows


def _make_writable_and_retry(func: Callable[[str], object], path: str, _error: object) -> None:
    """Git marks its object files read-only; on Windows they must be made writable first."""
    try:
        func(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        func(path)


# --- rendering the files ---------------------------------------------------------------------


def _render_files(items: Sequence[CatalogItem], rng: random.Random) -> dict[str, _RenderedFile]:
    """Render every file of the demo repo. Values are drawn in catalog order, so the same
    seed and catalog always give the same values."""
    templates = jinja2.Environment(
        loader=jinja2.PackageLoader("securegate.demo", "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - the templates are source code, not HTML
    )
    plants: dict[str, list[tuple[CatalogItem, fakes.Plant]]] = {}
    for item in items:
        plant = fakes.build_plant(
            item.kind, fakes.file_type(item.file), rng, name=item.name, variant=item.variant
        )
        plants.setdefault(item.file, []).append((item, plant))
    history_files = {item.file for item in items if item.placement == "history-only"}
    paths = [*BASE_FILES, *(path for path in plants if path not in BASE_FILES)]
    return {
        path: _render_file(templates, path, plants.get(path, []), path in history_files)
        for path in paths
    }


def _render_file(
    templates: jinja2.Environment,
    path: str,
    plants: list[tuple[CatalogItem, fakes.Plant]],
    history_only: bool,
) -> _RenderedFile:
    app_file = BASE_FILES.get(path)
    name = app_file.template if app_file else GENERIC_TEMPLATES[fakes.file_type(path)]
    text = templates.get_template(name).render(
        app_name=APP_NAME, file_name=PurePosixPath(path).name, plant_here=PLANT_MARKER
    )
    lines = text.split("\n")
    rows = [i for i, line in enumerate(lines) if PLANT_MARKER in line]
    if not rows:
        return _RenderedFile(text, (), history_only)
    row = rows[0]
    indent = lines[row].split(PLANT_MARKER)[0]
    if len(rows) > 1 or indent.strip():
        raise DemoError(f"template {name} must have one marker line with nothing else on it")
    inserted: list[str] = []
    planted: list[tuple[CatalogItem, fakes.Value, int]] = []
    for item, plant in plants:
        first_line = row + 1 + len(inserted)  # 1-based line number of this plant's first line
        planted.extend((item, value, first_line + value.offset) for value in plant.values)
        inserted.extend(indent + line if line else line for line in plant.lines)
    new_text = "\n".join([*lines[:row], *inserted, *lines[row + 1 :]])
    return _RenderedFile(new_text, tuple(planted), history_only)


# --- the Git history -------------------------------------------------------------------------


class _Git:
    """Runs git in the demo repo with a fixed identity and none of the user's Git settings."""

    def __init__(self, program: Path, repo: Path, scratch: Path) -> None:
        empty_config = scratch / "empty.gitconfig"
        empty_config.touch()
        self._no_templates = scratch / "no-templates"
        self._no_templates.mkdir()
        self._program = program
        self._repo = repo
        self._env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        self._env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=str(empty_config),
            GIT_AUTHOR_NAME=AUTHOR_NAME,
            GIT_AUTHOR_EMAIL=AUTHOR_EMAIL,
            GIT_COMMITTER_NAME=AUTHOR_NAME,
            GIT_COMMITTER_EMAIL=AUTHOR_EMAIL,
        )

    def init(self) -> None:
        self.run("init", "-q", "-b", "main", f"--template={self._no_templates}")
        info = self._repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "exclude").write_text(f"/{MARKER_FILE}\n/{GROUND_TRUTH_FILE}\n", encoding="utf-8")

    def commit(self, message: str, number: int) -> str:
        """Commit everything with a fixed date and return the commit's SHA."""
        when = (FIRST_COMMIT_DATE + timedelta(days=number)).isoformat()
        self.run("add", "-A")
        self.run("commit", "-q", "-m", message, date=when)
        return self.run("rev-parse", "HEAD")

    def run(self, *args: str, date: str | None = None) -> str:
        env = (
            self._env
            if date is None
            else {**self._env, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        )
        done = subprocess.run(  # noqa: S603 - absolute path to git; arguments built here
            [
                str(self._program),
                "-C",
                str(self._repo),
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.autocrlf=false",
                *args,
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if done.returncode != 0:
            raise DemoError(f"git {args[0]} failed: {done.stderr.strip()[-300:]}")
        return done.stdout.strip()


def _write_history(
    out: Path, files: dict[str, _RenderedFile], git: _Git
) -> tuple[list[str], dict[str, str]]:
    """Commit the files following the STORY; return the commits and each file's commit."""
    history = sorted(path for path, file in files.items() if file.history_only)
    extra = [path for path in files if path not in BASE_FILES and path not in history]
    commits: list[str] = []
    commit_of: dict[str, str] = {}
    for step in STORY:
        if step.history == "remove":
            if history:
                for path in history:
                    (out / path).unlink()
                commits.append(git.commit(step.message, len(commits)))
            continue
        batch = list(step.files)
        if step.history == "add":
            batch += history
        batch += [
            path
            for path in extra
            if path not in commit_of and (step.rest or _top_folder(path) in step.folders)
        ]
        if not batch:
            continue
        for path in batch:
            target = out / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(files[path].text, encoding="utf-8", newline="\n")
            commit_of[path] = ""  # claimed; the SHA is filled in below
        sha = git.commit(step.message, len(commits))
        commits.append(sha)
        commit_of.update(dict.fromkeys(batch, sha))
    return commits, commit_of


def _top_folder(path: str) -> str:
    parts = PurePosixPath(path).parts
    return parts[0] if len(parts) > 1 else ""


# --- ground truth ----------------------------------------------------------------------------


def _planted_lines(
    files: dict[str, _RenderedFile], commits: list[str], commit_of: dict[str, str]
) -> list[PlantedLine]:
    order = {sha: position for position, sha in enumerate(commits)}
    rows = [
        PlantedLine(
            file=path,
            line=line,
            commit=commit_of[path],
            kind=item.kind,
            is_secret=item.is_secret,
            expected=item.expected,
            placement=item.placement,
            raw=value.raw,
            parts=value.parts,
        )
        for path, file in files.items()
        for item, value, line in file.planted
    ]
    return sorted(rows, key=lambda row: (order[row.commit], row.file, row.line))


def _write_ground_truth(path: Path, rows: Sequence[PlantedLine]) -> None:
    """Write ground_truth.csv: where each planted value is and what should happen. No values."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(GROUND_TRUTH_COLUMNS)
        for row in rows:
            secret = "true" if row.is_secret else "false"
            writer.writerow([row.file, row.line, row.commit, row.kind, secret, row.expected])
