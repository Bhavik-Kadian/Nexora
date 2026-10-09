"""The menu that Start SecureGate.cmd opens (`securegate menu`).

A scripted keyboard types the answers, and a recorder stands in for the securegate commands, so
nothing is built or scanned. The exception is the leak test: it builds the demo for real and
scans it through the real pipeline, with a fake Gitleaks.
"""

import json
import re
import shlex
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from fake_code_scanners import FakeBandit, FakeSemgrep, Spot
from fake_gitleaks import FakeGitleaks, report_for_demo
from fake_trufflehog import FakeTruffleHog, finding
from helpers import (
    GITLEAKS_CONFIG,
    POLICY_FILE,
    REPO_ROOT,
    SEMGREP_RULES,
    TRUFFLEHOG_CONFIG,
    git_installed,
    leaked,
)
from securegate.agents.fix_pr import LAST_FIX
from securegate.cli import build_parser, main
from securegate.demo.generator import MARKER_FILE, DemoResult
from securegate.demo.pull_requests import LAST_DEMO
from securegate.demo.scenarios import NAMES as SCENARIOS
from securegate.errors import ConfigError, SecureGateError
from securegate.menu import art
from securegate.menu.app import (
    AI_CHOICES,
    ASK_AGENTS,
    CHOICES,
    GATE_CHOICES,
    GATE_DEMOS,
    run_menu,
    terminal_lines,
)
from securegate.menu.terminal import Terminal
from securegate.outputs.markdown import MARKER
from securegate.policy import load_policy


class Keyboard:
    """Types one scripted answer per question, and keeps everything the menu showed."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.shown: list[str] = []

    def ask(self, prompt: str) -> str:
        self.shown.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def say(self, text: str) -> None:
        self.shown.append(text)


PR_URL = "https://github.com/demo-owner/demo-repo/pull/7"
FIX_URL = "https://github.com/demo-owner/demo-repo/pull/8"


def note_demo_pr(scenario: str, number: int = 7) -> None:
    """Leave the note that a successful `securegate demo-pr` leaves."""
    LAST_DEMO.parent.mkdir(parents=True, exist_ok=True)
    note = {
        "number": number,
        "url": PR_URL.replace("/7", f"/{number}"),
        "branch": f"demo/{scenario}-20261006-093015",
        "scenario": scenario,
        "title": "a payment key in the code",
        "expected": "red. Rule 8 (provider-keys) blocks the token.",
    }
    LAST_DEMO.write_text(json.dumps(note), encoding="utf-8")


@dataclass
class Commands:
    """Stands in for the securegate commands: records each one, then exits with the chosen code.
    A successful demo-repo leaves the marker file, and a successful demo-pr its note, like the
    real ones."""

    exit_codes: dict[str, int] = field(default_factory=dict)
    ran: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str]) -> int:
        self.ran.append(list(argv))
        code = self.exit_codes.get(argv[0], 0)
        if argv[0] == "demo-repo" and code == 0:
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / MARKER_FILE).touch()
        if argv[0] == "demo-pr" and code == 0:
            note_demo_pr(argv[1])
        if argv[0] == "agent-fix" and code == 0:
            LAST_FIX.parent.mkdir(parents=True, exist_ok=True)
            LAST_FIX.write_text(json.dumps({"url": FIX_URL, "branch": "demo/fix-x"}), "utf-8")
        return code

    @property
    def names(self) -> list[str]:
        return [argv[0] for argv in self.ran]


@dataclass
class Dashboards:
    """Stands in for the dashboard: records the report, then waits like the real one."""

    opened: list[Path] = field(default_factory=list)

    def __call__(self, report: Path, wait: Callable[[], object]) -> int:
        self.opened.append(report)
        wait()
        return 0


@dataclass
class MenuRun:
    exit_code: int
    keyboard: Keyboard
    commands: Commands
    dashboards: Dashboards
    urls: list[str]  # the pages the menu opened in the browser

    @property
    def text(self) -> str:
        return "\n".join(self.keyboard.shown)


def run(
    *answers: str,
    commands: Commands | None = None,
    open_dashboard: Callable[[Path, Callable[[], object]], object] | None = None,
    gitleaks: str | None = "8.30.1",
    scanners: bool = False,
    ai_ready: bool = False,
) -> MenuRun:
    """`scanners`: whether TruffleHog, Semgrep and Bandit count as installed."""
    keyboard = Keyboard(*answers)
    commands = commands or Commands()
    dashboards = Dashboards()
    urls: list[str] = []
    terminal = Terminal(ask=keyboard.ask, say=keyboard.say, columns=lambda: 120)
    code = run_menu(
        terminal,
        run_command=commands,
        open_dashboard=open_dashboard or dashboards,
        gitleaks_version=gitleaks,
        program_found=lambda program: scanners,
        open_url=urls.append,
        ai_ready=lambda: ai_ready,
    )
    return MenuRun(code, keyboard, commands, dashboards, urls)


@pytest.fixture(autouse=True)
def folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A SecureGate folder with the real policy. The demo project would go next to it."""
    home = tmp_path / "SecureGate"
    home.mkdir()
    shutil.copy(POLICY_FILE, home / "policy.yaml")
    monkeypatch.chdir(home)
    return home


def a_project(tmp_path: Path, name: str = "my project", *, git: bool = True) -> Path:
    project = tmp_path / name
    project.mkdir()
    if git:
        (project / ".git").mkdir()
    return project


# --- the first screen -------------------------------------------------------------------------


@pytest.mark.parametrize("answer", ["q", "Q", " quit ", "exit"])
def test_q_closes_the_menu_with_exit_code_0(answer: str) -> None:
    menu = run(answer)
    assert menu.exit_code == 0
    assert menu.commands.ran == []


def test_the_first_screen_shows_the_art_the_status_and_every_choice() -> None:
    text = run("q").text
    for line in art.render(art.banner(117, unicode=True), color=False):
        assert line in text
    assert art.TAGLINE in text
    assert "SecureGate 0.1.0, Gitleaks 8.30.1, rules in policy.yaml" in text
    assert "not built yet (1 builds it)" in text
    assert "Last scan   none yet" in text
    for key, label, _ in CHOICES:
        assert re.search(rf"^\s+{key}  {label}", text, re.MULTILINE)


def test_the_status_says_what_is_missing(folder: Path) -> None:
    (folder / "policy.yaml").unlink()
    text = run("q", gitleaks=None).text
    assert "Gitleaks not found (scans need it)" in text
    assert "no policy.yaml here (start SecureGate in its folder)" in text


def test_the_status_shows_the_result_of_the_last_scan(sample_report: Path, folder: Path) -> None:
    shutil.copy(sample_report, folder / "findings-demo.json")
    text = run("q").text
    assert re.search(
        r"Last scan   findings-demo\.json: BLOCKED \(\d+ block, \d+ warn, \d+ ignore\)", text
    )


def test_an_unknown_choice_says_what_to_type() -> None:
    menu = run("10", "q")
    assert "Type a number from 1 to 9 or A, or Q to quit, then press Enter." in menu.text
    assert menu.commands.ran == []


# --- 1: the demo project ----------------------------------------------------------------------


def test_the_demo_is_built_the_first_time_only() -> None:
    menu = run("1", "n", "1", "n", "q")
    assert menu.commands.names == ["demo-repo", "scan", "scan"]


def test_the_demo_is_built_and_scanned_like_make_demo_and_make_scan_demo() -> None:
    menu = run("1", "n", "q")
    demo, scan = (build_parser().parse_args(argv) for argv in menu.commands.ran)
    assert (Path(demo.out), demo.seed, demo.force) == (Path("../securegate-demo"), 42, True)
    assert Path(scan.path) == Path(demo.out)
    assert (scan.mode, scan.out) == ("repo", "findings-demo.json")  # the whole history


def test_each_command_is_shown_before_it_runs() -> None:
    text = run("1", "n", "q").text
    demo = Path("../securegate-demo")
    assert f"> securegate scan {demo} --mode repo --out findings-demo.json" in text


def test_enter_after_a_scan_opens_the_dashboard_on_that_scan() -> None:
    menu = run("1", "", "", "q")  # scan, Enter: open the dashboard, Enter: close it, quit
    assert menu.dashboards.opened == [Path("findings-demo.json")]
    assert "Press Enter to close the dashboard and go back to the menu." in menu.text
    assert menu.exit_code == 0


def test_blocked_secrets_in_the_demo_are_the_expected_result() -> None:
    menu = run("1", "n", "q", commands=Commands({"scan": 1}))
    assert "That is the expected result" in menu.text


@pytest.mark.parametrize("scan_exit", [2, 3, -1])
def test_a_failed_scan_never_offers_the_dashboard(scan_exit: int) -> None:
    menu = run("1", "", "q", commands=Commands({"scan": scan_exit}))
    assert "The scan failed: the lines above say why." in menu.text
    assert "Open the results in the dashboard?" not in menu.text
    assert menu.dashboards.opened == []


def test_a_demo_that_could_not_be_built_is_not_scanned() -> None:
    menu = run("1", "", "q", commands=Commands({"demo-repo": 2}))
    assert menu.commands.names == ["demo-repo"]
    assert "The demo project could not be built" in menu.text


# --- 4: a project of yours --------------------------------------------------------------------


def test_a_git_project_is_scanned_through_its_whole_history(tmp_path: Path) -> None:
    project = a_project(tmp_path)
    menu = run("4", f'"{project}"', "", "n", "q")  # a dragged-in path comes in quotes
    assert menu.commands.ran == [
        ["scan", str(project.resolve()), "--mode", "repo", "--out", "findings.json"]
    ]


def test_answering_n_scans_only_the_files_as_they_are_now(tmp_path: Path) -> None:
    menu = run("4", str(a_project(tmp_path)), "n", "n", "q")
    assert menu.commands.ran[0][2:4] == ["--mode", "dir"]


def test_a_folder_that_is_not_a_git_project_is_scanned_as_files(tmp_path: Path) -> None:
    menu = run("4", str(a_project(tmp_path, git=False)), "n", "q")
    assert menu.commands.ran[0][2:4] == ["--mode", "dir"]
    assert "It is not a Git project" in menu.text


def test_nothing_is_scanned_when_nothing_is_there(tmp_path: Path) -> None:
    menu = run("4", str(tmp_path / "missing"), "", "q")
    assert menu.commands.ran == []
    assert "There is nothing at" in menu.text


def test_enter_alone_goes_back_without_scanning() -> None:
    assert run("4", "", "q").commands.ran == []


# --- 5: the dashboard -------------------------------------------------------------------------


def test_the_dashboard_needs_a_scan_first() -> None:
    menu = run("5", "", "q")
    assert menu.dashboards.opened == []
    assert "There is no scan report yet (findings-demo.json)" in menu.text


def test_the_dashboard_shows_the_last_scan_of_this_session(tmp_path: Path, folder: Path) -> None:
    (folder / "findings-demo.json").write_text("{}", encoding="utf-8")
    (folder / "findings.json").write_text("{}", encoding="utf-8")
    menu = run("5", "", "4", str(a_project(tmp_path, git=False)), "n", "5", "", "q")
    assert menu.dashboards.opened == [Path("findings-demo.json"), Path("findings.json")]


def test_a_dashboard_that_cannot_start_says_why_and_the_menu_goes_on(folder: Path) -> None:
    (folder / "findings-demo.json").write_text("{}", encoding="utf-8")

    def busy(report: Path, wait: Callable[[], object]) -> int:
        raise ConfigError("cannot start the dashboard on port 5000 (in use)")

    menu = run("5", "", "q", open_dashboard=busy)
    assert "securegate: error: cannot start the dashboard on port 5000" in menu.text
    assert menu.exit_code == 0


# --- 6, 7, 8: the rules, rebuilding the demo, the setup ---------------------------------------


def test_the_rules_are_listed_in_order_with_their_decisions() -> None:
    menu = run("6", "", "q")
    listed = [line.split()[:3] for line in menu.keyboard.shown if re.match(r"\s+\d+\. ", line)]
    policy = load_policy(POLICY_FILE)
    assert listed == [
        [f"{rule.number}.", rule.decision.upper(), rule.name] for rule in policy.rules
    ]  # numbered like the policy table, as in the reports
    assert "notepad policy.yaml" in menu.text


def test_a_broken_policy_is_reported_and_the_menu_goes_on(folder: Path) -> None:
    (folder / "policy.yaml").write_text("version: 1\nrules: []\n", encoding="utf-8")
    menu = run("6", "", "q")
    assert "securegate: error:" in menu.text
    assert menu.exit_code == 0


@pytest.mark.parametrize("answer", ["n", ""])
def test_rebuilding_the_demo_asks_first(answer: str) -> None:
    menu = run("1", "n", "7", answer, "q")
    assert menu.commands.names == ["demo-repo", "scan"]  # only the first build


def test_rebuilding_the_demo_starts_it_over_like_make_demo() -> None:
    menu = run("1", "n", "7", "y", "", "q")
    rebuild = build_parser().parse_args(menu.commands.ran[-1])
    assert (rebuild.command, rebuild.seed, rebuild.force) == ("demo-repo", 42, True)


def test_check_the_setup_shows_versions_rules_and_the_laptop_gate(folder: Path) -> None:
    menu = run("8", "", "q")
    assert menu.commands.ran == [["version"]]
    assert f"Rules: policy.yaml, {len(load_policy(POLICY_FILE).rules)} rules" in menu.text
    assert "Laptop gate: off (turn it on with: make hooks)" in menu.text

    hooks = folder / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").touch()
    assert "Laptop gate: on" in run("8", "", "q").text


# --- every command, leaks and the end of the input ---------------------------------------------


def test_every_command_the_menu_runs_is_a_real_securegate_command(tmp_path: Path) -> None:
    project = a_project(tmp_path)
    menu = run(
        "1", "n", "2", "n", "n", "4", str(project), "", "", "", "n",
        "7", "y", "", "8", "",
        "9", "1", "n", "n", "", "6", "n", "", "7", "n", "", "8", "y", "", "9", "", "b",
        "q",
        scanners=True,
    )  # fmt: skip
    assert sorted(set(menu.commands.names)) == [
        "ci-report",
        "demo-cleanup",
        "demo-pr",
        "demo-repo",
        "doctor",
        "scan",
        "version",
    ]
    for argv in menu.commands.ran:
        try:
            build_parser().parse_args(argv)
        except SystemExit:
            pytest.fail(f"`securegate {' '.join(argv)}` is not a valid command")


@pytest.mark.skipif(not git_installed(), reason="git is not installed")
def test_the_menu_never_shows_a_planted_secret(
    demo_repo: DemoResult, folder: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shutil.copy(GITLEAKS_CONFIG, folder / ".gitleaks.toml")
    fake = FakeGitleaks(report=report_for_demo(demo_repo))  # "finds" every planted value
    keyboard = Keyboard("1", "n", "6", "", "8", "", "q")
    code = run_menu(
        Terminal(ask=keyboard.ask, say=keyboard.say, columns=lambda: 120),
        run_command=lambda argv: main(list(argv), runner=fake),
        open_dashboard=Dashboards(),
        gitleaks_version="8.30.1",
    )
    printed = capsys.readouterr()
    everything = "\n".join(keyboard.shown) + printed.out + printed.err

    assert code == 0
    assert (folder.parent / "securegate-demo" / MARKER_FILE).is_file()  # really built
    assert "-> BLOCKED (exit code 1)" in printed.out  # really scanned
    assert leaked(demo_repo.planted, everything) == []


# --- 2 and 3: all four scanners, and the pull request comment ---------------------------------

SAMPLE_COMMENT = "\n".join(
    [
        MARKER,
        "### SecureGate: BLOCKED (exit code 1)",
        "",
        "**This pull request cannot be merged.** Fix every blocked finding below.",
        "",
        "> [!CAUTION]",
        "> **Semgrep did not run**: it failed (exit code 2). The other scanners still decided.",
        "",
        "| Decision | Rule | Where | Masked value | Found by | Live check |",
        "|---|---|---|---|---|---|",
        "| BLOCK | rule 8: provider-keys | `web/checkout.js:2` | `acme****DHqJ` | Gitleaks | x |",
        "",
        "#### Fix `web/checkout.js:2`: an ACME Pay key (`acme****DHqJ`)",
        "",
        "- [ ] Revoke the key at ACME Pay. In the ACME Pay dashboard, revoke this key, and do it "
        "before anything else, because anyone who can see the pull request can read it.",
        "",
        "Deleting the line is not enough: the key stays in Git history.",
        "",
        "<details>",
        "<summary>Ignored: 1, because they are not secrets</summary>",
        "",
        "- `docs/payments.md:10` (`acme****xxxx`): rule 3: placeholders.",
        "",
        "</details>",
    ]
)


def write_comment(folder: Path, name: str = "demo-comment.md") -> None:
    (folder / "reports").mkdir(exist_ok=True)
    (folder / "reports" / name).write_text(SAMPLE_COMMENT, encoding="utf-8")


def test_the_status_says_whether_all_four_scanners_are_ready() -> None:
    ready = "Gitleaks, TruffleHog, Semgrep and Bandit: all four ready"
    assert ready in run("q", scanners=True).text
    missing = "Gitleaks only. Missing: TruffleHog, Semgrep, Bandit (install with: make scanners)"
    assert missing in run("q").text


def test_all_four_scanners_need_make_scanners_first() -> None:
    menu = run("2", "", "q")
    assert menu.commands.ran == []
    assert "Install them once with: make scanners" in menu.text


def parsed(argv: list[str]) -> dict[str, object]:
    """The parsed command, with paths compared as paths (Windows writes them with a backslash)."""
    options = vars(build_parser().parse_args(argv))
    return {
        name: Path(value) if isinstance(value, str) else value for name, value in options.items()
    }


def test_choice_2_runs_exactly_what_make_scan_demo_all_runs() -> None:
    menu = run("2", "n", "n", "q", scanners=True)
    assert menu.commands.names == ["demo-repo", "scan"]
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    (recipe,) = re.findall(r"^scan-demo-all:\n\t(.*)$", makefile, re.MULTILINE)
    make_argv = shlex.split(recipe.replace("$(DEMO_DIR)", "../securegate-demo"))
    make_argv = make_argv[make_argv.index("securegate") + 1 :]
    assert parsed(menu.commands.ran[1]) == parsed(make_argv)


def test_the_four_scanner_scan_keeps_live_checks_off_and_offers_the_comment(folder: Path) -> None:
    write_comment(folder)
    menu = run("2", "", "n", "q", scanners=True)  # show the comment, then no dashboard
    scan = build_parser().parse_args(menu.commands.ran[-1])
    assert (scan.scanners, scan.no_verification) == ("all", True)
    assert "live checks stay off" in menu.text
    assert "SecureGate: BLOCKED (exit code 1)" in menu.text
    assert menu.dashboards.opened == []


def test_choice_3_shows_the_comment_in_the_terminal(folder: Path) -> None:
    write_comment(folder)
    text = run("3", "", "q").text
    assert MARKER not in text
    assert "SecureGate: BLOCKED (exit code 1)" in text and "### " not in text
    assert "CAUTION: Semgrep did not run: it failed (exit code 2)." in text
    assert re.search(r"BLOCK +rule 8: provider-keys +web/checkout\.js:2 +acme\*{4}DHqJ", text)
    assert "Deleting the line is not enough: the key stays in Git history." in text
    assert "Ignored: 1, because they are not secrets" in text and "<details>" not in text


def test_choice_3_needs_a_four_scanner_scan_first() -> None:
    text = run("3", "", "q").text
    assert f"There is no pull request comment yet ({Path('reports/demo-comment.md')})" in text
    assert "Choose 2" in text


def test_a_project_of_yours_can_use_all_four_scanners_without_live_checks(tmp_path: Path) -> None:
    project = a_project(tmp_path)
    menu = run("4", str(project), "", "", "", "n", "q", scanners=True)
    assert menu.commands.ran == [
        [
            "scan", str(project.resolve()), "--mode", "repo", "--out", "findings.json",
            "--scanners", "all", "--comment", str(Path("reports/comment.md")),
            "--no-verification",
        ]
    ]  # fmt: skip
    assert "Choose 3 on the menu" in menu.text


def test_live_checks_on_a_project_of_yours_happen_only_when_asked(tmp_path: Path) -> None:
    menu = run("4", str(a_project(tmp_path)), "", "", "y", "n", "q", scanners=True)
    assert "--no-verification" not in menu.commands.ran[0]


def test_files_on_disk_are_scanned_with_gitleaks_alone(tmp_path: Path) -> None:
    menu = run("4", str(a_project(tmp_path, git=False)), "n", "q", scanners=True)
    assert "--scanners" not in menu.commands.ran[0]  # the others only read Git history


def test_terminal_lines_make_the_comment_readable() -> None:
    lines = terminal_lines(SAMPLE_COMMENT + "\nbell \x07 and escape \x1b[2J", width=60, color=False)
    text = "\n".join(lines)
    assert lines[0] == "SecureGate: BLOCKED (exit code 1)"
    flat = " ".join(text.split())
    assert "This pull request cannot be merged. Fix every blocked finding below." in flat
    revoke = [line for line in lines if line.startswith("- [ ] Revoke")]
    assert revoke and all(len(line) <= 60 for line in lines if not line.startswith("|"))
    following = lines[lines.index(revoke[0]) + 1]
    assert following.startswith("      ")  # the wrapped checklist item stays indented
    assert "\x07" not in text and "\x1b" not in text  # no terminal control characters


def test_a_table_that_fits_is_shown_in_columns() -> None:
    lines = terminal_lines(SAMPLE_COMMENT, width=100, color=False)
    header = next(line for line in lines if line.startswith("Decision"))
    row = next(line for line in lines if line.startswith("BLOCK"))
    for title, value in (("Rule", "rule 8"), ("Where", "web/"), ("Found by", "Gitleaks")):
        assert header.index(title) == row.index(value)
    assert not any("|" in line for line in lines)


def test_a_table_too_wide_for_the_terminal_keeps_its_rows_whole() -> None:
    lines = terminal_lines(SAMPLE_COMMENT, width=60, color=False)
    row = "| BLOCK | rule 8: provider-keys | web/checkout.js:2 | acme****DHqJ | Gitleaks | x |"
    assert row in lines
    assert not any("---" in line for line in lines)  # the line under the header is left out


def test_a_pipe_inside_a_cell_stays_in_its_cell() -> None:
    table = "| File | Masked value |\n|---|---|\n| `a\\|b.py:1` | `acme****x\\|yz` |"
    assert terminal_lines(table, width=60, color=False) == [
        "File      Masked value",
        "a|b.py:1  acme****x|yz",
    ]


@pytest.mark.skipif(not git_installed(), reason="git is not installed")
def test_the_four_scanner_choice_and_its_comment_never_show_a_planted_secret(
    demo_repo: DemoResult, folder: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for config in (GITLEAKS_CONFIG, TRUFFLEHOG_CONFIG):
        shutil.copy(config, folder / config.name)
    (folder / "rules").mkdir()
    shutil.copy(SEMGREP_RULES, folder / "rules" / SEMGREP_RULES.name)
    at_head = [p for p in demo_repo.planted if p.placement != "history-only"]
    scanners = {
        "trufflehog": FakeTruffleHog(
            findings=[
                finding(file=p.file, line=p.line, value=p.raw, commit=p.commit)
                for p in demo_repo.planted
            ]
        ),
        "semgrep": FakeSemgrep(
            spots=[Spot("detected-secret", p.file, p.parts[0]) for p in at_head]
        ),
        "bandit": FakeBandit(
            spots=[Spot("B105", p.file, p.parts[0]) for p in at_head if p.file.endswith(".py")]
        ),
    }
    gitleaks = FakeGitleaks(report=report_for_demo(demo_repo))  # "finds" every planted value
    keyboard = Keyboard("2", "", "n", "3", "", "q")  # scan, show the comment, no dashboard, 3
    code = run_menu(
        Terminal(ask=keyboard.ask, say=keyboard.say, columns=lambda: 120),
        run_command=lambda argv: main(list(argv), runner=gitleaks, tool_runners=scanners),
        open_dashboard=Dashboards(),
        gitleaks_version="8.30.1",
        program_found=lambda program: True,
    )
    printed = capsys.readouterr()
    everything = "\n".join(keyboard.shown) + printed.out + printed.err

    assert code == 0
    assert "Scanners: Gitleaks 8.30.1; TruffleHog 3.97.9" in printed.out  # really scanned
    assert "SecureGate: BLOCKED (exit code 1)" in everything  # the comment was shown
    assert leaked(demo_repo.planted, everything) == []


def test_the_menu_stops_with_exit_code_2_when_its_input_ends(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def nothing_more(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", nothing_more)
    assert main(["menu"], runner=FakeGitleaks()) == 2
    assert "securegate: error: the menu's input ended" in capsys.readouterr().err


def test_ctrl_c_at_the_menu_stops_it_with_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def ctrl_c(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", ctrl_c)
    assert main(["menu"], runner=FakeGitleaks()) == 2
    assert "securegate: interrupted" in capsys.readouterr().err


def test_the_menu_stops_when_its_input_ends_even_in_the_middle_of_a_choice() -> None:
    with pytest.raises(SecureGateError, match="input ended"):
        run("4")  # asks for a folder, but no answer comes


# --- 9: the merge gate on GitHub --------------------------------------------------------------

CI_REPORT_ARGS = ["--wait", "--no-open", "--out", "findings-ci.json"]


def test_9_shows_the_merge_gate_screen_and_b_goes_back() -> None:
    menu = run("9", "b", "q")
    assert menu.exit_code == 0
    assert menu.commands.ran == []
    assert "The merge gate on GitHub" in menu.text
    assert "Last demo   none yet" in menu.text
    for key, _, label, expected in GATE_DEMOS:
        assert re.search(rf"^\s+{key}  {label}\s+expected: {expected}$", menu.text, re.MULTILINE)
    for key, label, _ in GATE_CHOICES:
        assert re.search(rf"^\s+{key}  {label}", menu.text, re.MULTILINE)


def test_the_demo_choices_are_the_five_scenarios_of_demo_pr() -> None:
    assert [scenario for _, scenario, _, _ in GATE_DEMOS] == list(SCENARIOS)


def test_a_demo_pull_request_opens_in_the_browser_and_its_result_in_the_dashboard() -> None:
    # 9, 2: the leak; Enter: open it in the browser; Enter: wait for the result; Enter: open
    # the dashboard; Enter: close it; B: back; Q: quit.
    menu = run("9", "2", "", "", "", "", "b", "q")
    assert menu.commands.ran == [["demo-pr", "leak"], ["ci-report", "--pr", "7", *CI_REPORT_ARGS]]
    assert menu.urls == [PR_URL]
    assert menu.dashboards.opened == [Path("findings-ci.json")]
    assert "> securegate demo-pr leak" in menu.text
    assert menu.exit_code == 0


def test_the_screen_shows_the_last_demo_pull_request() -> None:
    note_demo_pr("leak", number=12)
    text = run("9", "b", "q").text
    assert f"Last demo   #12, a payment key in the code: {PR_URL.replace('/7', '/12')}" in text


def test_the_browser_and_the_wait_are_offered_not_forced() -> None:
    menu = run("9", "1", "n", "n", "", "b", "q")
    assert menu.commands.ran == [["demo-pr", "clean"]]
    assert menu.urls == []
    assert "Choose 6 later to see its result." in menu.text


def test_a_demo_pull_request_that_failed_offers_nothing() -> None:
    menu = run("9", "2", "", "b", "q", commands=Commands({"demo-pr": 2}))
    assert menu.commands.names == ["demo-pr"]
    assert "No pull request was opened: the lines above say why." in menu.text
    assert "Open it in your browser?" not in menu.text
    assert menu.urls == []


def test_a_link_that_is_not_a_github_pull_request_is_never_opened() -> None:
    class Elsewhere(Commands):
        def __call__(self, argv: Sequence[str]) -> int:
            code = super().__call__(argv)
            note = json.loads(LAST_DEMO.read_text(encoding="utf-8"))
            note["url"] = "https://example.com/demo-owner/demo-repo/pull/7"
            LAST_DEMO.write_text(json.dumps(note), encoding="utf-8")
            return code

    menu = run("9", "2", "", "b", "q", commands=Elsewhere())
    assert menu.urls == []
    assert "Open it in your browser?" not in menu.text


def test_6_needs_a_demo_pull_request_first() -> None:
    menu = run("9", "6", "", "b", "q")
    assert menu.commands.ran == []
    assert "There is no demo pull request yet. Choose 1 to 5 to open one first." in menu.text


def test_6_waits_for_the_result_of_the_last_demo_pull_request() -> None:
    note_demo_pr("leak", number=12)
    menu = run("9", "6", "n", "", "b", "q")
    assert menu.commands.ran == [["ci-report", "--pr", "12", *CI_REPORT_ARGS]]
    assert "Pull request #12, a payment key in the code. Expected: red." in menu.text
    assert menu.dashboards.opened == []


def test_7_opens_the_newest_gate_report_in_the_dashboard() -> None:
    menu = run("9", "7", "", "", "b", "q")
    assert menu.commands.ran == [["ci-report", "--no-open", "--out", "findings-ci.json"]]
    assert menu.dashboards.opened == [Path("findings-ci.json")]


def test_after_a_gate_report_choice_5_opens_that_report(folder: Path) -> None:
    menu = run("9", "7", "n", "", "b", "5", "", "q")  # then 5 on the main menu
    assert menu.dashboards.opened == []  # the report was never downloaded in this test
    assert "There is no scan report yet (findings-ci.json)." in menu.text


def test_a_report_that_could_not_be_downloaded_never_opens_the_dashboard() -> None:
    menu = run("9", "7", "", "b", "q", commands=Commands({"ci-report": 2}))
    assert "No report was downloaded: the lines above say why." in menu.text
    assert menu.dashboards.opened == []


@pytest.mark.parametrize("answer", ["", "n", "no"])
def test_8_asks_before_closing_every_demo_pull_request(answer: str) -> None:
    menu = run("9", "8", answer, "b", "q")
    assert menu.commands.ran == []


def test_8_closes_every_demo_pull_request_when_asked() -> None:
    menu = run("9", "8", "y", "", "b", "q")
    assert menu.commands.ran == [["demo-cleanup"]]


def test_9_checks_that_everything_is_ready() -> None:
    menu = run("9", "9", "", "b", "q", commands=Commands({"doctor": 1}))
    assert menu.commands.ran == [["doctor"]]
    assert "Each FAIL line says what to fix." in menu.text


def test_an_unknown_choice_on_the_merge_gate_screen_says_what_to_type() -> None:
    menu = run("9", "x", "b", "q")
    assert "Type a number from 1 to 9 or F, or B to go back, then press Enter." in menu.text
    assert menu.commands.ran == []


def test_an_error_on_the_merge_gate_screen_is_shown_and_the_menu_goes_on() -> None:
    class Broken(Commands):
        def __call__(self, argv: Sequence[str]) -> int:
            raise ConfigError("no policy here")

    menu = run("9", "9", "", "b", "q", commands=Broken())
    assert "securegate: error: no policy here" in menu.text
    assert "Press Enter to go back to the merge gate menu." in menu.text
    assert menu.exit_code == 0


# --- A: the AI agents -------------------------------------------------------------------------


def test_a_shows_the_ai_agents_screen_and_b_goes_back() -> None:
    menu = run("a", "b", "q")
    assert menu.exit_code == 0
    assert menu.commands.ran == []
    assert "The AI agents" in menu.text
    for key, label, _ in AI_CHOICES:
        assert re.search(rf"^\s+{key}  {label}", menu.text, re.MULTILINE)


def test_the_first_screen_says_whether_the_ai_agents_are_ready() -> None:
    assert "AI agents   not set up (A, then 4, sets them up)" in run("q").text
    assert "AI agents   ready (A asks them about the last scan)" in run("q", ai_ready=True).text


def test_asking_needs_the_agents_set_up_first() -> None:
    menu = run("a", "1", "", "b", "q")
    assert menu.commands.ran == []
    assert "The AI agents are not set up yet. Choose 4 to set them up first." in menu.text


def test_asking_needs_a_scan_first() -> None:
    menu = run("a", "1", "", "b", "q", ai_ready=True)
    assert menu.commands.ran == []
    assert "There is no scan yet." in menu.text


def test_asking_runs_the_agents_on_the_last_scan(folder: Path) -> None:
    (folder / "findings-demo.json").write_text("{}", encoding="utf-8")
    menu = run("a", "1", "", "b", "q", ai_ready=True)
    assert menu.commands.ran == [["agents", "--report", "findings-demo.json"]]


def test_asking_rewrites_the_comment_made_from_that_scan(folder: Path) -> None:
    (folder / "findings-demo.json").write_text("{}", encoding="utf-8")
    (folder / "reports").mkdir()
    (folder / "reports" / "demo-comment.md").write_text("comment", encoding="utf-8")
    menu = run("a", "1", "", "b", "q", ai_ready=True)
    comment = str(Path("reports") / "demo-comment.md")
    assert menu.commands.ran == [["agents", "--report", "findings-demo.json", "--comment", comment]]


def test_setting_up_offers_to_check_the_connection() -> None:
    menu = run("a", "4", "", "", "b", "q")
    assert menu.commands.names == ["ai-setup", "ai-check"]
    menu = run("a", "4", "n", "", "b", "q")
    assert menu.commands.names == ["ai-setup"]


def test_checking_the_connection_runs_ai_check() -> None:
    assert run("a", "5", "", "b", "q").commands.names == ["ai-check"]


def test_after_a_scan_the_agents_are_offered_only_when_set_up() -> None:
    assert ASK_AGENTS not in run("1", "n", "q").text
    menu = run("1", "", "n", "q", ai_ready=True)  # scan, ask the agents, no dashboard
    assert menu.commands.names[-2:] == ["scan", "agents"]
    assert menu.commands.ran[-1] == ["agents", "--report", "findings-demo.json"]
    declined = run("1", "n", "n", "q", ai_ready=True)
    assert declined.commands.names[-1] == "scan"


def test_their_advice_is_shown_in_the_terminal(sample_report: Path, folder: Path) -> None:
    data = json.loads(sample_report.read_text(encoding="utf-8"))
    block = next(f for f in data["findings"] if f["decision"] == "block")
    data["advice"] = {
        "status": "ok",
        "model": "gpt-5.4-mini",
        "agents": {"triage": {"status": "ok", "note": None}},
        "triage": [
            {
                "finding": block["id"],
                "verdict": "likely_real",
                "confidence": "high",
                "why": "A live key in application code.",
                "next_step": "Revoke it at the provider.",
            }
        ],
    }
    (folder / "findings-demo.json").write_text(json.dumps(data), encoding="utf-8")
    text = run("a", "2", "", "b", "q").text
    assert "AI advice from gpt-5.4-mini: the policy decided, not the AI." in text
    assert (
        f"{block['file']}:{block['line']} {block['masked_value']}: likely real, high confidence."
        in text
    )
    assert "A live key in application code. Next: Revoke it at the provider." in text


def test_the_ai_commands_are_real_securegate_commands(folder: Path) -> None:
    (folder / "findings-demo.json").write_text("{}", encoding="utf-8")
    menu = run("a", "1", "", "4", "", "", "5", "", "b", "q", ai_ready=True)
    assert menu.commands.names == ["agents", "ai-setup", "ai-check", "ai-check"]
    for argv in menu.commands.ran:
        build_parser().parse_args(argv)


# --- F: the fix agent, on the merge gate screen ---------------------------------------------------


def test_f_needs_a_demo_pull_request_and_the_ai_agents() -> None:
    assert "There is no demo pull request yet." in run("9", "f", "", "b", "q", ai_ready=True).text
    note_demo_pr("leak")
    menu = run("9", "f", "", "b", "q")
    assert "set them up first, with A, then 4" in menu.text
    assert menu.commands.ran == []


def test_f_opens_a_fix_pull_request_and_offers_it_in_the_browser() -> None:
    note_demo_pr("leak", number=12)
    menu = run("9", "f", "", "", "b", "q", ai_ready=True)
    assert menu.commands.ran == [["agent-fix", "--pr", "12"]]
    assert menu.urls == [FIX_URL]
    build_parser().parse_args(menu.commands.ran[0])


def test_f_that_opened_nothing_offers_nothing() -> None:
    note_demo_pr("leak")
    menu = run("9", "f", "", "b", "q", ai_ready=True, commands=Commands({"agent-fix": 2}))
    assert "No fix pull request was opened" in menu.text
    assert menu.urls == []
