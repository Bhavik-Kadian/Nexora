"""The double-click launcher, Start SecureGate.cmd: it checks the setup, then opens the menu.

On every OS: it only runs securegate commands that exist, in the right order, and cmd.exe can
read it. On Windows it really runs, but with a stand-in for SecureGate that records each command
and exits with the code a test chooses: no menu opens. tests/test_menu.py tests the menu.
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import venv
from dataclasses import dataclass
from pathlib import Path

import pytest

from helpers import REPO_ROOT
from securegate.cli import build_parser

LAUNCHER = REPO_ROOT / "Start SecureGate.cmd"
TEXT = LAUNCHER.read_text(encoding="utf-8")
VARIABLES = dict(re.findall(r'^set "(\w+)=(.*)"$', TEXT, re.MULTILINE))
RUNS = re.compile(r'^"%PYTHON%" -m securegate (.*?)(?: \|\| goto :\w+)?$', re.MULTILINE)
SUGGESTS = re.compile(r'^set "HINT=.*\\securegate (.*)"$', re.MULTILINE)


def commands(pattern: re.Pattern[str]) -> list[list[str]]:
    """The arguments of each securegate command the pattern finds, with variables filled in."""
    found = []
    for line in pattern.findall(TEXT):
        lexer = shlex.shlex(re.sub(r"%(\w+)%", lambda m: VARIABLES[m.group(1)], line), posix=True)
        lexer.whitespace_split = True
        lexer.escape = ""  # cmd.exe has no backslash escapes: ..\securegate-demo stays as it is
        found.append(list(lexer))
    return found


# --- what it runs (every OS) ------------------------------------------------------------------


def test_it_checks_the_setup_then_opens_the_menu() -> None:
    assert [args[0] for args in commands(RUNS)] == ["version", "menu"]


@pytest.mark.parametrize("args", commands(RUNS) + commands(SUGGESTS), ids=" ".join)
def test_every_command_it_runs_or_suggests_exists(args: list[str]) -> None:
    try:
        build_parser().parse_args(args)
    except SystemExit:
        pytest.fail(f"`securegate {' '.join(args)}` is no longer a valid command")


def test_cmd_exe_can_read_it() -> None:
    data = LAUNCHER.read_bytes()
    assert data.isascii()
    assert b"\n" not in data.replace(b"\r\n", b"")  # CRLF line endings only


# --- how it behaves (Windows) ---------------------------------------------------------------

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="the launcher needs cmd.exe")

STAND_IN = '''"""Stands in for SecureGate: records the command, then exits with the chosen code."""
import os
import sys

command = sys.argv[1]
with open(os.environ["LAUNCHER_LOG"], "a", encoding="utf-8") as log:
    log.write(command + "\\n")
raise SystemExit(int(os.environ.get("EXIT_" + command.upper().replace("-", "_"), "0")))
'''


@dataclass
class LauncherRun:
    exit_code: int
    out: str
    commands: list[str]  # the securegate commands it ran, in order


@pytest.fixture(scope="module")
def stand_in(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A folder for PYTHONPATH that holds the stand-in `securegate` package."""
    folder = tmp_path_factory.mktemp("stand-in")
    (folder / "securegate").mkdir()
    (folder / "securegate" / "__init__.py").touch()
    (folder / "securegate" / "__main__.py").write_text(STAND_IN, encoding="utf-8")
    return folder


@pytest.fixture(scope="module")
def securegate_folder(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """What the launcher looks for next to itself, with a bare Python in .venv (made once)."""
    folder = tmp_path_factory.mktemp("template") / "SecureGate"
    (folder / "src" / "securegate").mkdir(parents=True)
    (folder / "pyproject.toml").touch()
    shutil.copy(LAUNCHER, folder)
    venv.create(folder / ".venv", with_pip=False)
    return folder


@pytest.fixture
def folder(securegate_folder: Path, tmp_path: Path) -> Path:
    """A fresh copy for each test."""
    return Path(shutil.copytree(securegate_folder, tmp_path / "SecureGate"))


def run_launcher(
    folder: Path, stand_in: Path, answer: str = "", path: str | None = None, **exit_codes: int
) -> LauncherRun:
    log = folder.parent / "commands.log"
    log.unlink(missing_ok=True)
    env = {
        **os.environ,
        "PYTHONPATH": str(stand_in),
        "LAUNCHER_LOG": str(log),
        **{f"EXIT_{step.upper()}": str(code) for step, code in exit_codes.items()},
    }
    if path is not None:
        env["PATH"] = path
    done = subprocess.run(
        ["cmd", "/d", "/c", "call", str(folder / LAUNCHER.name)],
        input=f"{answer}\n",  # an answer for its question, if it asks one, then a key for pause
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,  # its window title must not change ours
    )
    ran = log.read_text(encoding="utf-8").split() if log.exists() else []
    return LauncherRun(done.returncode, done.stdout, ran)


@windows_only
def test_it_opens_the_menu_and_choosing_q_closes_the_window(folder: Path, stand_in: Path) -> None:
    run = run_launcher(folder, stand_in)
    assert run.commands == ["version", "menu"]
    assert "SecureGate stopped" not in run.out
    assert run.exit_code == 0


@windows_only
@pytest.mark.parametrize("menu_exit", [2, 1, -1])
def test_a_menu_that_stops_with_an_error_keeps_the_window_open(
    folder: Path, stand_in: Path, menu_exit: int
) -> None:
    run = run_launcher(folder, stand_in, menu=menu_exit)
    assert run.commands == ["version", "menu"]
    assert "SecureGate stopped" in run.out
    assert run.exit_code == 1


@windows_only
def test_a_broken_setup_never_opens_the_menu_and_says_what_to_do(
    folder: Path, stand_in: Path
) -> None:
    run = run_launcher(folder, stand_in, version=2)
    assert run.commands == ["version"]
    assert "Delete that folder" in run.out
    assert run.exit_code == 1


@windows_only
def test_nothing_is_installed_without_asking(folder: Path, stand_in: Path) -> None:
    shutil.rmtree(folder / ".venv")
    run = run_launcher(folder, stand_in, answer="N")
    assert "Set it up now" in run.out
    assert "Nothing was changed" in run.out
    assert not (folder / ".venv").exists()
    assert (run.commands, run.exit_code) == ([], 1)


@windows_only
def test_answering_yes_starts_the_setup_and_explains_a_failed_one(
    folder: Path, stand_in: Path
) -> None:
    system32 = str(Path(os.environ["SYSTEMROOT"], "System32"))  # cmd and choice, but no Python
    if shutil.which("py", path=system32):
        pytest.skip("this computer keeps the Python launcher in System32")
    shutil.rmtree(folder / ".venv")
    run = run_launcher(folder, stand_in, answer="Y", path=system32)
    assert "Setting it up needs Python 3.12" in run.out
    assert (run.commands, run.exit_code) == ([], 1)


@windows_only
def test_a_copy_outside_the_securegate_folder_explains_what_to_do(
    tmp_path: Path, stand_in: Path
) -> None:
    desktop = tmp_path / "Desktop"
    desktop.mkdir()
    shutil.copy(LAUNCHER, desktop)
    run = run_launcher(desktop, stand_in)
    assert "must stay in the SecureGate folder" in run.out
    assert "Desktop (create shortcut)" in run.out
    assert (run.commands, run.exit_code) == ([], 1)
