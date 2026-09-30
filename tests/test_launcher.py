"""The double-click launcher, Start SecureGate.cmd.

On every OS: it only runs securegate commands that exist, in the right order, and cmd.exe can
read it. On Windows it really runs, but with a stand-in for SecureGate that records each command
and exits with the code a test chooses: nothing is built or scanned, and no browser opens.
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


def test_it_checks_the_setup_builds_the_demo_scans_it_and_opens_the_dashboard() -> None:
    assert [args[0] for args in commands(RUNS)] == ["version", "demo-repo", "scan", "ui"]


@pytest.mark.parametrize("args", commands(RUNS) + commands(SUGGESTS), ids=" ".join)
def test_every_command_it_runs_or_suggests_exists(args: list[str]) -> None:
    try:
        build_parser().parse_args(args)
    except SystemExit:
        pytest.fail(f"`securegate {' '.join(args)}` is no longer a valid command")


def test_the_dashboard_shows_the_scan_of_the_demo_it_built() -> None:
    parsed = {args[0]: build_parser().parse_args(args) for args in commands(RUNS)}
    assert parsed["scan"].path == parsed["demo-repo"].out
    assert parsed["scan"].mode == "repo"  # the whole history, so the deleted key is found too
    assert parsed["ui"].report == parsed["scan"].out
    assert parsed["ui"].open


def test_cmd_exe_can_read_it() -> None:
    data = LAUNCHER.read_bytes()
    assert data.isascii()
    assert b"\n" not in data.replace(b"\r\n", b"")  # CRLF line endings only


# --- how it behaves (Windows) ---------------------------------------------------------------

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="the launcher needs cmd.exe")

STAND_IN = '''"""Stands in for SecureGate: records the command, then exits with the chosen code."""
import os
import sys
from pathlib import Path

command = sys.argv[1]
with open(os.environ["LAUNCHER_LOG"], "a", encoding="utf-8") as log:
    log.write(command + "\\n")
if command == "demo-repo":
    out = Path(sys.argv[sys.argv.index("--out") + 1])
    out.mkdir(parents=True, exist_ok=True)
    (out / ".securegate-demo").touch()
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
    """A fresh copy for each test; the demo project would go next to it."""
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
def test_the_demo_is_built_the_first_time_only(folder: Path, stand_in: Path) -> None:
    first = run_launcher(folder, stand_in)
    second = run_launcher(folder, stand_in)

    assert first.commands == ["version", "demo-repo", "scan", "ui"]
    assert second.commands == ["version", "scan", "ui"]
    assert "The demo project is ready" in second.out
    assert (first.exit_code, second.exit_code) == (0, 0)


@windows_only
def test_blocked_secrets_are_expected_and_still_open_the_dashboard(
    folder: Path, stand_in: Path
) -> None:
    run = run_launcher(folder, stand_in, scan=1)
    assert run.commands == ["version", "demo-repo", "scan", "ui"]
    assert "That is the expected result" in run.out
    assert run.exit_code == 0


@windows_only
@pytest.mark.parametrize("scan_exit", [2, 3, -1])
def test_a_failed_scan_never_opens_the_dashboard(
    folder: Path, stand_in: Path, scan_exit: int
) -> None:
    run = run_launcher(folder, stand_in, scan=scan_exit)
    assert run.commands == ["version", "demo-repo", "scan"]
    assert "SecureGate stopped" in run.out
    assert run.exit_code == 1


@windows_only
@pytest.mark.parametrize(
    ("step", "ran", "hint"),
    [
        ("version", ["version"], "Delete that folder"),
        ("demo_repo", ["version", "demo-repo"], "SecureGate stopped"),
        ("ui", ["version", "demo-repo", "scan", "ui"], "--port 5050"),
    ],
)
def test_a_failed_step_stops_there_and_says_what_to_do(
    folder: Path, stand_in: Path, step: str, ran: list[str], hint: str
) -> None:
    run = run_launcher(folder, stand_in, **{step: 2})
    assert run.commands == ran
    assert hint in run.out
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
