"""The menu that Start SecureGate.cmd opens (`securegate menu`).

A scripted keyboard types the answers, and a recorder stands in for the securegate commands, so
nothing is built or scanned. The exception is the leak test: it builds the demo for real and
scans it through the real pipeline, with a fake Gitleaks.
"""

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
from securegate.cli import build_parser, main
from securegate.demo.generator import MARKER_FILE, DemoResult
from securegate.errors import ConfigError, SecureGateError
from securegate.menu import art
from securegate.menu.app import CHOICES, run_menu, terminal_lines
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


@dataclass
class Commands:
    """Stands in for the securegate commands: records each one, then exits with the chosen code.
    A successful demo-repo leaves the marker file, like the real one."""

    exit_codes: dict[str, int] = field(default_factory=dict)
    ran: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str]) -> int:
        self.ran.append(list(argv))
        code = self.exit_codes.get(argv[0], 0)
        if argv[0] == "demo-repo" and code == 0:
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / MARKER_FILE).touch()
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

    @property
    def text(self) -> str:
        return "\n".join(self.keyboard.shown)


def run(
    *answers: str,
    commands: Commands | None = None,
    open_dashboard: Callable[[Path, Callable[[], object]], object] | None = None,
    gitleaks: str | None = "8.30.1",
    scanners: bool = False,
) -> MenuRun:
    """`scanners`: whether TruffleHog, Semgrep and Bandit count as installed."""
    keyboard = Keyboard(*answers)
    commands = commands or Commands()
    dashboards = Dashboards()
    terminal = Terminal(ask=keyboard.ask, say=keyboard.say, columns=lambda: 120)
    code = run_menu(
        terminal,
        run_command=commands,
        open_dashboard=open_dashboard or dashboards,
        gitleaks_version=gitleaks,
        program_found=lambda program: scanners,
    )
    return MenuRun(code, keyboard, commands, dashboards)


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
    menu = run("9", "q")
    assert "Type a number from 1 to 8, or Q to quit, then press Enter." in menu.text
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
        "7", "y", "", "8", "", "q",
        scanners=True,
    )  # fmt: skip
    assert sorted(set(menu.commands.names)) == ["demo-repo", "scan", "version"]
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
