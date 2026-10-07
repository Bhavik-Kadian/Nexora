"""The menu that Start SecureGate.cmd opens: SecureGate without typing commands.

Each choice runs the securegate commands a person would type, through `run_command`, and shows
each command before running it. So the exit codes, masking and fail-closed checks are exactly
those of the CLI. Apart from that, the menu only reads: policy.yaml for the rules, the last
report through the dashboard's loader, which refuses any value that is not masked, the pull
request comment that a scan wrote (made from that same checked report), and the note that
`securegate demo-pr` leaves about the pull request it opened (reports/demo-pr.json). It opens
that pull request's page in the browser when asked, and only if its link is a GitHub pull
request link. Choice A asks the AI agents about the last scan (securegate agents), and shows
their advice from the checked report.
"""

import re
import textwrap
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from securegate import __version__
from securegate.demo.generator import MARKER_FILE
from securegate.demo.pull_requests import LAST_DEMO, LastDemo, load_last_demo
from securegate.errors import SecureGateError
from securegate.finding import DECISIONS
from securegate.menu.art import TAGLINE, banner, render
from securegate.menu.terminal import BOLD, CLEAR, CYAN, GREEN, GREY, RED, YELLOW, Terminal, paint
from securegate.outputs.markdown import MARKER, VERDICT_WORDS
from securegate.policy import load_policy
from securegate.programs import find_program
from securegate.ui.report_view import ReportView, load_report

EXIT_PASS = 0  # securegate's exit codes, as in cli.py
EXIT_BLOCK = 1

DEMO_DIR = Path("../securegate-demo")  # where make demo builds it, next to the SecureGate folder
DEMO_SEED = "42"
DEMO_REPORT = Path("findings-demo.json")
OWN_REPORT = Path("findings.json")
REPORTS = Path("reports")  # what make scan-demo-all writes besides the report; Git ignores it
DEMO_COMMENT = REPORTS / "demo-comment.md"
OWN_COMMENT = REPORTS / "comment.md"
CI_REPORT = Path("findings-ci.json")  # what ci-report downloads from the merge gate
OTHER_SCANNERS = ("trufflehog", "semgrep", "bandit")  # installed by make scanners
POLICY = Path("policy.yaml")
LAPTOP_GATE = Path(".git/hooks/pre-commit")  # what make hooks installs
MARGIN = "  "
REVEAL_SECONDS = 0.04  # between the lines of the art, on the first screen only

CHOICES = (
    ("1", "Scan the demo project", "with Gitleaks, its whole history (built the first time)"),
    ("2", "Scan it with all four scanners", "Gitleaks, TruffleHog, Semgrep and Bandit"),
    ("3", "Show the pull request comment", "what the merge gate posts on GitHub"),
    ("4", "Scan a project of yours", "type its folder, or drag it in here"),
    ("5", "Open the dashboard", "the last scan, in your browser"),
    ("6", "Show the rules", "what policy.yaml blocks, warns and ignores"),
    ("7", "Rebuild the demo project", "start it over, exactly as new"),
    ("8", "Check the setup", "versions, scanners, rules and the laptop gate"),
    ("9", "The merge gate on GitHub", "demo pull requests, their results and reports"),
    ("A", "AI agents", "triage, fixes and an incident plan for the last scan"),
    ("Q", "Quit", ""),
)
# The AI agents screen (A).
AI_CHOICES = (
    ("1", "Ask about the last scan", "they get masked findings, and code without its secrets"),
    ("2", "Show their advice here", "triage, suggested fixes and the incident plan"),
    ("3", "Open it in the dashboard", "the AI advice page, and each finding's panels"),
    ("4", "Set up the AI agents", "the Azure endpoint, the model and its key (typed hidden)"),
    ("5", "Check the connection", "one tiny request, with no code in it"),
    ("B", "Back to the main menu", ""),
)
ASK_AGENTS = (
    "Ask the AI agents about these findings? They get the masked findings, and code with every "
    "secret taken out. [Y/n] "
)
# The merge gate screen (9). First the demo pull requests: key, `securegate demo-pr` scenario,
# label and what the merge gate should say about it.
GATE_DEMOS = (
    ("1", "clean", "A harmless change", "green"),
    ("2", "leak", "A payment key in the code", "red, rule 8 blocks the key"),
    ("3", "deleted-later", "A key deleted in a later commit", "still red, every commit counts"),
    ("4", "decoys", "Decoys that look like secrets", "green, each one explained"),
    ("5", "risky", "Risky handling of secrets", "green, with warnings"),
)
GATE_CHOICES = (
    ("6", "See the result", "of the last demo pull request, then its report"),
    ("7", "Open the newest gate report", "of the last pull request checked, in the dashboard"),
    ("8", "Close every demo pull request", "and delete the demo/ branches"),
    ("9", "Check that all is ready", "scanners, rules, gh login and GitHub's settings"),
    ("B", "Back to the main menu", ""),
)
LABEL_WIDTH = 32
QUIT = ("q", "quit", "exit")
BACK = ("b", "back", "q", "")
DECISION_STYLES = {"block": BOLD + RED, "warn": BOLD + YELLOW, "ignore": GREY}
RESULT_STYLES = {"PASS": BOLD + GREEN, "BLOCKED": BOLD + RED}

RunCommand = Callable[[Sequence[str]], int]
OpenDashboard = Callable[[Path, Callable[[], object]], object]
OpenUrl = Callable[[str], object]


class InputEnded(SecureGateError):
    """Nobody can answer the menu any more: its input ended."""


def run_menu(
    terminal: Terminal,
    *,
    run_command: RunCommand,
    open_dashboard: OpenDashboard,
    gitleaks_version: str | None,
    program_found: Callable[[str], bool] | None = None,
    open_url: OpenUrl | None = None,
    ai_ready: Callable[[], bool] | None = None,
) -> int:
    """Show the menu until the person chooses Q, then return exit code 0.

    `run_command` runs one securegate command and returns its exit code. `open_dashboard`
    shows a report in the dashboard until the function it is given returns. `program_found`
    says whether a scanner such as trufflehog is installed, `open_url` opens a pull request's
    page in the browser, and `ai_ready` says whether the AI agents are set up (tests pass their
    own).
    """
    found = program_found or _installed
    url = open_url or webbrowser.open
    menu = Menu(terminal, run_command, open_dashboard, gitleaks_version, found, url)
    menu.ai_ready = ai_ready or (lambda: False)
    return menu.run()


def _installed(program: str) -> bool:
    return find_program(program) is not None


@dataclass
class Menu:
    terminal: Terminal
    run_command: RunCommand
    open_dashboard: OpenDashboard
    gitleaks_version: str | None  # None: Gitleaks was not found
    program_found: Callable[[str], bool] = field(default=_installed)
    open_url: OpenUrl = field(default=webbrowser.open)
    ai_ready: Callable[[], bool] = field(default=lambda: False)
    last_report: Path = DEMO_REPORT  # the report the dashboard opens
    last_comment: Path = DEMO_COMMENT  # the pull request comment that 3 shows
    hint: str = ""  # shown under the choices on the next screen

    def run(self) -> int:
        actions: dict[str, Callable[[], bool]] = {
            "1": self.scan_demo,
            "2": self.scan_demo_all,
            "3": self.show_comment,
            "4": self.scan_project,
            "5": self.dashboard,
            "6": self.rules,
            "7": self.rebuild_demo,
            "8": self.check_setup,
            "9": self.merge_gate,
            "a": self.ai_agents,
        }
        first = True
        while True:
            self.home(reveal=first)
            first = False
            choice = self.ask(f"{MARGIN}Type a number and press Enter: ").strip().lower()
            self.hint = ""
            if choice in QUIT:
                return EXIT_PASS
            action = actions.get(choice)
            if action is None:
                self.hint = "Type a number from 1 to 9 or A, or Q to quit, then press Enter."
                continue
            self.perform(action, back_to="the menu")

    def perform(self, action: Callable[[], bool], *, back_to: str) -> None:
        """Run one choice. Its result stays on screen until Enter when it returns True."""
        self.say("")
        try:
            wait = action()
        except InputEnded:
            raise
        except SecureGateError as err:
            self.say(f"securegate: error: {err}")
            wait = True
        if wait:
            self.ask(f"\n{MARGIN}Press Enter to go back to {back_to}. ")

    # --- the first screen ---------------------------------------------------------------------

    def home(self, *, reveal: bool) -> None:
        columns = self.terminal.columns()
        art = banner(columns - len(MARGIN) - 1, unicode=self.terminal.unicode)
        self.say(CLEAR if self.terminal.color else "")
        for line in render(art, color=self.terminal.color):
            self.say(MARGIN + line)
            if reveal and self.terminal.color:
                self.terminal.pause(REVEAL_SECONDS)
        indent = MARGIN + " " * art.name_column
        if columns - len(indent) < 40:
            indent = MARGIN
        for line in textwrap.wrap(TAGLINE, width=max(20, columns - len(indent) - 1)):
            self.say(indent + self.paint(line, GREY))
        self.say("")
        for label, value in self.status():
            self.say(f"{MARGIN}{self.paint(f'{label:<12}', GREY)}{value}")
        self.say("")
        self.say(f"{MARGIN}What do you want to do?")
        self.say("")
        for key, label, note in CHOICES:
            self.choice_line(key, label, note)
        self.say("")
        if self.hint:
            self.say(MARGIN + self.paint(self.hint, YELLOW))

    def choice_line(self, key: str, label: str, note: str) -> None:
        shown = self.paint(key, BOLD + CYAN)
        label = label.ljust(LABEL_WIDTH) if len(label) < LABEL_WIDTH else f"{label} "
        self.say(f"{MARGIN}  {shown}  {label}{self.paint(note, GREY)}".rstrip())

    def status(self) -> list[tuple[str, str]]:
        if self.gitleaks_version:
            gitleaks = f"Gitleaks {self.gitleaks_version}"
        else:
            gitleaks = self.paint("Gitleaks not found (scans need it)", RED)
        if POLICY.is_file():
            rules = f"rules in {POLICY}"
        else:
            rules = self.paint(f"no {POLICY} here (start SecureGate in its folder)", RED)
        return [
            ("Setup", f"SecureGate {__version__}, {gitleaks}, {rules}"),
            ("Scanners", self.scanners_status()),
            ("Demo", self.demo_status()),
            ("Last scan", self.last_scan()),
            ("AI agents", self.ai_status()),
        ]

    def ai_status(self) -> str:
        if self.ai_ready():
            return "ready (A asks them about the last scan)"
        return "not set up (A, then 4, sets them up)"

    def scanners_status(self) -> str:
        missing = [name for name in OTHER_SCANNERS if not self.program_found(name)]
        if not missing:
            return "Gitleaks, TruffleHog, Semgrep and Bandit: all four ready (2 and 4 use them)"
        names = {"trufflehog": "TruffleHog", "semgrep": "Semgrep", "bandit": "Bandit"}
        absent = ", ".join(names[name] for name in missing)
        return self.paint(f"Gitleaks only. Missing: {absent} (install with: make scanners)", YELLOW)

    def demo_status(self) -> str:
        return f"ready in {DEMO_DIR}" if self.demo_ready() else "not built yet (1 builds it)"

    def last_scan(self) -> str:
        if not self.last_report.exists():
            return "none yet"
        report = load_report(self.last_report)
        if not isinstance(report, ReportView):
            return f"{self.last_report}: {report.title}"
        result = self.paint(report.result, RESULT_STYLES.get(report.result, BOLD + YELLOW))
        counts = ", ".join(f"{report.count(decision)} {decision}" for decision in DECISIONS)
        return f"{self.last_report}: {result} ({counts})"

    # --- the choices: each returns True to keep its result on screen until Enter -----------

    def scan_demo(self) -> bool:
        if not self.demo_ready():
            self.tell(f"Building the demo project in {DEMO_DIR} (the first time only)...")
            if self.build_demo() != EXIT_PASS:
                self.tell("The demo project could not be built: the lines above say why.")
                return True
            self.say("")
        self.tell("Scanning the demo project's whole Git history...")
        code = self.securegate("scan", str(DEMO_DIR), "--mode", "repo", "--out", str(DEMO_REPORT))
        if code == EXIT_BLOCK:
            self.tell(
                "That is the expected result: the demo project is full of planted fake secrets."
            )
        return self.after_scan(code, DEMO_REPORT)

    def scan_demo_all(self) -> bool:
        if not self.program_found("trufflehog"):
            self.tell(
                "Scanning with all four scanners needs TruffleHog, Semgrep and Bandit. Install "
                "them once with: make scanners (it needs the internet)."
            )
            return True
        if not self.demo_ready():
            self.tell(f"Building the demo project in {DEMO_DIR} (the first time only)...")
            if self.build_demo() != EXIT_PASS:
                self.tell("The demo project could not be built: the lines above say why.")
                return True
            self.say("")
        self.tell(
            "Scanning the demo project with all four scanners. TruffleHog's live checks stay "
            "off: the demo's fake keys must never be sent to a real provider."
        )
        code = self.securegate(
            "scan", str(DEMO_DIR), "--mode", "repo", "--scanners", "all", "--no-verification",
            "--out", str(DEMO_REPORT),
            "--comment", str(DEMO_COMMENT),
            "--summary", str(REPORTS / "demo-summary.md"),
            "--sarif", str(REPORTS / "demo.sarif"),
        )  # fmt: skip
        if code == EXIT_BLOCK:
            self.tell(
                "That is the expected result: the demo project is full of planted fake secrets."
            )
        if code in (EXIT_PASS, EXIT_BLOCK):
            self.last_comment = DEMO_COMMENT
            self.say("")
            if self.yes("Show the comment a pull request would get? [Y/n] ", default=True):
                self.say("")
                self.print_comment(DEMO_COMMENT)
        return self.after_scan(code, DEMO_REPORT)

    def show_comment(self) -> bool:
        if not self.last_comment.is_file():
            self.tell(
                f"There is no pull request comment yet ({self.last_comment}). Choose 2 to scan "
                "the demo project with all four scanners first."
            )
            return True
        self.print_comment(self.last_comment)
        return True

    def print_comment(self, path: Path) -> None:
        self.tell(
            "On GitHub, the merge gate posts this as a comment on the pull request, and shows it "
            "on the check's page too. Masked values only."
        )
        self.say("")
        width = max(30, self.terminal.columns() - len(MARGIN) - 1)
        markdown = path.read_text(encoding="utf-8", errors="replace")
        for line in terminal_lines(markdown, width=width, color=self.terminal.color):
            self.say(f"{MARGIN}{line}" if line else "")

    def scan_project(self) -> bool:
        self.tell(
            "Which folder? Type its path, or drag the folder into this window. "
            "Press Enter alone to go back."
        )
        text = self.ask(f"{MARGIN}Folder: ").strip().strip("\"'").strip()
        if not text:
            return False
        target = Path(text).expanduser().resolve()
        if not target.exists():
            self.tell(f"There is nothing at {target}.")
            return True
        if (target / ".git").exists():
            history = self.yes(
                "Scan its whole Git history? [Y/n] (n: only the files as they are now) ",
                default=True,
            )
            mode = "repo" if history else "dir"
        else:
            self.tell("It is not a Git project, so SecureGate scans its files as they are now.")
            mode = "dir"
        argv = ["scan", str(target), "--mode", mode, "--out", str(OWN_REPORT)]
        four = (
            mode == "repo"
            and self.program_found("trufflehog")
            and self.yes(
                "Use all four scanners (Gitleaks, TruffleHog, Semgrep and Bandit)? [Y/n] ",
                default=True,
            )
        )
        if four:
            argv += ["--scanners", "all", "--comment", str(OWN_COMMENT)]
            live = self.yes(
                "Let TruffleHog ask each provider whether the keys it finds still work? This "
                "sends every key it finds to its provider. [y/N] ",
                default=False,
            )
            if not live:
                argv.append("--no-verification")
        self.say("")
        code = self.securegate(*argv)
        if four and code in (EXIT_PASS, EXIT_BLOCK):
            self.last_comment = OWN_COMMENT
            self.tell("Choose 3 on the menu to see the comment a pull request would get.")
        return self.after_scan(code, OWN_REPORT)

    def after_scan(self, code: int, report: Path) -> bool:
        """After a finished scan, offer the dashboard. After a failed one, never: it would only
        show that the scan failed."""
        self.last_report = report
        if code not in (EXIT_PASS, EXIT_BLOCK):
            self.tell(self.paint("The scan failed: the lines above say why.", RED))
            return True
        if self.ai_ready():
            self.say("")
            if self.yes(ASK_AGENTS, default=True):
                self.say("")
                self.ask_agents(report)
        self.say("")
        if not self.yes("Open the results in the dashboard? [Y/n] ", default=True):
            return False
        return self.show_dashboard(report)

    def dashboard(self) -> bool:
        if not self.last_report.is_file():
            self.tell(
                f"There is no scan report yet ({self.last_report}). "
                "Choose 1 or 2 to scan the demo project first."
            )
            return True
        return self.show_dashboard(self.last_report)

    def show_dashboard(self, report: Path) -> bool:
        self.tell("Opening the dashboard in your browser...")
        self.open_dashboard(report, self.wait_for_enter)
        return False

    def wait_for_enter(self) -> None:
        self.ask(f"{MARGIN}Press Enter to close the dashboard and go back to the menu. ")

    def rules(self) -> bool:
        policy = load_policy(POLICY)
        self.tell(
            f"The rules in {POLICY}. They are checked from top to bottom, and the first rule "
            "that matches a finding decides."
        )
        self.say("")
        width = max(30, self.terminal.columns() - 15)
        for position, rule in enumerate(policy.rules, start=1):
            number = rule.number or position  # the policy table's number, as in the reports
            decision = self.paint(f"{rule.decision.upper():<6}", DECISION_STYLES[rule.decision])
            self.say(f"{MARGIN}{number:>2}. {decision}  {rule.name}")
            for line in textwrap.wrap(rule.reason, width=width):
                self.say(f"{MARGIN}            {self.paint(line, GREY)}")
        self.say("")
        self.tell(f"To change the rules, edit {POLICY}, for example with: notepad {POLICY}")
        return True

    def rebuild_demo(self) -> bool:
        if self.demo_ready() and not self.yes(
            f"This deletes the demo project in {DEMO_DIR} and builds it again, exactly as new. "
            "Go on? [y/N] ",
            default=False,
        ):
            return False
        self.say("")
        self.build_demo()
        return True

    def check_setup(self) -> bool:
        self.securegate("version")
        try:
            rules = f"{POLICY}, {len(load_policy(POLICY).rules)} rules"
        except SecureGateError as err:
            rules = self.paint(f"problem: {err}", RED)
        if LAPTOP_GATE.is_file():
            gate = self.paint("on", GREEN)
        else:
            gate = self.paint("off", YELLOW) + " (turn it on with: make hooks)"
        self.say(f"{MARGIN}Rules: {rules}")
        self.say(f"{MARGIN}Laptop gate: {gate}")
        self.say(f"{MARGIN}Demo: {self.demo_status()}")
        self.say(f"{MARGIN}Merge gate on GitHub: choose 9, then 9 to check it")
        return True

    # --- 9: the merge gate on GitHub ----------------------------------------------------------

    def merge_gate(self) -> bool:
        actions: dict[str, Callable[[], bool]] = {
            "6": self.gate_result,
            "7": self.newest_gate_report,
            "8": self.close_demos,
            "9": self.gate_doctor,
        }
        for key, scenario, _, _ in GATE_DEMOS:
            actions[key] = lambda scenario=scenario: self.open_demo(scenario)
        hint = ""
        while True:
            self.gate_home(hint)
            choice = self.ask(f"{MARGIN}Type a number and press Enter (B: back): ").strip().lower()
            hint = ""
            if choice in BACK:
                return False
            action = actions.get(choice)
            if action is None:
                hint = "Type a number from 1 to 9, or B to go back, then press Enter."
                continue
            self.perform(action, back_to="the merge gate menu")

    def gate_home(self, hint: str) -> None:
        self.say(CLEAR if self.terminal.color else "")
        self.say(MARGIN + self.paint("The merge gate on GitHub", BOLD + CYAN))
        self.say("")
        self.tell(
            "Every pull request to main is scanned by Gitleaks, TruffleHog, Semgrep and Bandit "
            "before it can be merged. A demo pull request shows the gate at work on GitHub, with "
            "fake values made at random. Never merge one."
        )
        self.say("")
        last = load_last_demo(LAST_DEMO)
        shown = f"#{last.number}, {last.title}: {last.url}" if last else "none yet"
        self.say(f"{MARGIN}{self.paint('Last demo'.ljust(12), GREY)}{shown}")
        self.say("")
        self.say(f"{MARGIN}Open a demo pull request:")
        self.say("")
        for key, _, label, expected in GATE_DEMOS:
            self.choice_line(key, label, f"expected: {expected}")
        self.say("")
        for key, label, note in GATE_CHOICES:
            self.choice_line(key, label, note)
        self.say("")
        if hint:
            self.say(MARGIN + self.paint(hint, YELLOW))

    def open_demo(self, scenario: str) -> bool:
        self.tell(
            "Opening a demo pull request on GitHub. SecureGate builds it from main in a "
            "temporary folder, so your own files stay as they are."
        )
        before = load_last_demo(LAST_DEMO)
        code = self.securegate("demo-pr", scenario)
        if code != EXIT_PASS:
            self.tell(self.paint("No pull request was opened: the lines above say why.", RED))
            return True
        last = load_last_demo(LAST_DEMO)
        if last is None or last == before:
            return True
        self.say("")
        if self.yes("Open it in your browser? [Y/n] ", default=True):
            self.open_url(last.url)
        self.say("")
        if not self.yes(
            "Wait here for the merge gate's result (about a minute)? [Y/n] ", default=True
        ):
            self.tell("Choose 6 later to see its result.")
            return True
        self.say("")
        return self.result_of(last)

    def gate_result(self) -> bool:
        last = load_last_demo(LAST_DEMO)
        if last is None:
            self.tell("There is no demo pull request yet. Choose 1 to 5 to open one first.")
            return True
        self.tell(f"Pull request #{last.number}, {last.title}. Expected: {last.expected}")
        self.say("")
        return self.result_of(last)

    def result_of(self, last: LastDemo) -> bool:
        code = self.securegate(
            "ci-report", "--pr", str(last.number), "--wait", "--no-open", "--out", str(CI_REPORT)
        )
        return self.after_gate_report(code)

    def newest_gate_report(self) -> bool:
        code = self.securegate("ci-report", "--no-open", "--out", str(CI_REPORT))
        return self.after_gate_report(code)

    def after_gate_report(self, code: int) -> bool:
        if code != EXIT_PASS:
            self.tell(self.paint("No report was downloaded: the lines above say why.", RED))
            return True
        self.last_report = CI_REPORT
        report = load_report(CI_REPORT)
        has_advice = isinstance(report, ReportView) and report.advice is not None
        if self.ai_ready() and not has_advice:
            self.say("")
            if self.yes(ASK_AGENTS, default=True):
                self.say("")
                self.ask_agents(CI_REPORT)
        self.say("")
        if not self.yes("Open the report in the dashboard? [Y/n] ", default=True):
            return True
        return self.show_dashboard(CI_REPORT)

    def close_demos(self) -> bool:
        if not self.yes(
            "This closes every open demo pull request and deletes every demo/ branch, on GitHub "
            "and here. Go on? [y/N] ",
            default=False,
        ):
            return False
        self.say("")
        self.securegate("demo-cleanup")
        return True

    def gate_doctor(self) -> bool:
        if self.securegate("doctor") == EXIT_BLOCK:
            self.say("")
            self.tell(
                "Each FAIL line says what to fix. The one-time setting on GitHub is explained in "
                "docs/merge-gate.md."
            )
        return True

    # --- A: the AI agents --------------------------------------------------------------------

    def ai_agents(self) -> bool:
        actions: dict[str, Callable[[], bool]] = {
            "1": self.ai_ask,
            "2": self.ai_show,
            "3": self.ai_dashboard,
            "4": self.ai_setup,
            "5": self.ai_check,
        }
        hint = ""
        while True:
            self.ai_home(hint)
            choice = self.ask(f"{MARGIN}Type a number and press Enter (B: back): ").strip().lower()
            hint = ""
            if choice in BACK:
                return False
            action = actions.get(choice)
            if action is None:
                hint = "Type a number from 1 to 5, or B to go back, then press Enter."
                continue
            self.perform(action, back_to="the AI agents menu")

    def ai_home(self, hint: str) -> None:
        self.say(CLEAR if self.terminal.color else "")
        self.say(MARGIN + self.paint("The AI agents", BOLD + CYAN))
        self.say("")
        self.tell(
            "Three AI agents advise on a scan: triage (a real secret, or a false alarm?), fix (the "
            "line rewritten to read an environment variable) and incident (what to do now about a "
            "leaked key). The policy still decides every finding, and the agents never see a "
            "whole secret."
        )
        self.say("")
        self.say(f"{MARGIN}{self.paint('AI'.ljust(12), GREY)}{self.ai_status()}")
        self.say(f"{MARGIN}{self.paint('Last scan'.ljust(12), GREY)}{self.advice_status()}")
        self.say("")
        for key, label, note in AI_CHOICES:
            self.choice_line(key, label, note)
        self.say("")
        if hint:
            self.say(MARGIN + self.paint(hint, YELLOW))

    def advice_status(self) -> str:
        if not self.last_report.is_file():
            return "none yet"
        report = load_report(self.last_report)
        if not isinstance(report, ReportView):
            return f"{self.last_report}: {report.title}"
        if report.advice is None:
            note = "advice withheld" if report.advice_note else "no advice yet"
            return f"{self.last_report}: {note}"
        return f"{self.last_report}: advice {report.advice.status}"

    def ai_ask(self) -> bool:
        if not self.ai_ready():
            self.tell("The AI agents are not set up yet. Choose 4 to set them up first.")
            return True
        if not self.last_report.is_file():
            self.tell("There is no scan yet. Scan something first: 1, 2 or 4 on the main menu.")
            return True
        if self.ask_agents(self.last_report) == EXIT_PASS:
            self.say("")
            self.tell("Choose 2 to read their advice here, or 3 for the dashboard.")
        return True

    def ask_agents(self, report: Path) -> int:
        """Run `securegate agents` on `report`; rewrite the matching pull request comment too."""
        argv = ["agents", "--report", str(report)]
        comment = {DEMO_REPORT: DEMO_COMMENT, OWN_REPORT: OWN_COMMENT}.get(report)
        if comment is not None and comment.is_file():
            argv += ["--comment", str(comment)]
        code = self.securegate(*argv)
        if code != EXIT_PASS:
            self.tell(self.paint("The agents could not be asked: the lines above say why.", RED))
        return code

    def ai_show(self) -> bool:
        if not self.last_report.is_file():
            self.tell("There is no scan yet. Scan something first: 1, 2 or 4 on the main menu.")
            return True
        report = load_report(self.last_report)
        if not isinstance(report, ReportView):
            self.tell(f"{report.title}. {report.detail}")
            return True
        width = max(30, self.terminal.columns() - len(MARGIN) - 1)
        for line in advice_lines(report, width=width, color=self.terminal.color):
            self.say(f"{MARGIN}{line}" if line else "")
        return True

    def ai_dashboard(self) -> bool:
        if not self.last_report.is_file():
            self.tell("There is no scan yet. Scan something first: 1, 2 or 4 on the main menu.")
            return True
        self.tell("In the dashboard, select AI advice at the top.")
        return self.show_dashboard(self.last_report)

    def ai_setup(self) -> bool:
        if self.securegate("ai-setup") == EXIT_PASS:
            self.say("")
            if self.yes("Check the connection now? [Y/n] ", default=True):
                self.say("")
                self.securegate("ai-check")
        return True

    def ai_check(self) -> bool:
        self.securegate("ai-check")
        return True

    # --- helpers ------------------------------------------------------------------------------

    def demo_ready(self) -> bool:
        return (DEMO_DIR / MARKER_FILE).is_file()

    def build_demo(self) -> int:
        return self.securegate("demo-repo", "--out", str(DEMO_DIR), "--seed", DEMO_SEED, "--force")

    def securegate(self, *argv: str) -> int:
        """Run one securegate command, showing it first, as a person would type it."""
        typed = " ".join(f'"{arg}"' if " " in arg else arg for arg in argv)
        self.say(self.paint(f"{MARGIN}> securegate {typed}", GREY))
        return self.run_command(list(argv))

    def yes(self, question: str, *, default: bool) -> bool:
        while True:
            answer = self.ask(MARGIN + question).strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.tell("Type y or n, or press Enter for the choice in capitals.")

    def ask(self, prompt: str) -> str:
        try:
            return self.terminal.ask(prompt)
        except EOFError:
            raise InputEnded(
                "the menu's input ended, so nobody can answer it. Open the menu in a terminal "
                "window; in scripts, use the other securegate commands."
            ) from None

    def say(self, text: str) -> None:
        self.terminal.say(text)

    def tell(self, text: str) -> None:
        """Show a message, wrapped to the window."""
        width = max(30, self.terminal.columns() - len(MARGIN) - 1)
        for line in textwrap.wrap(text, width=width) or [""]:
            self.say(MARGIN + line)

    def paint(self, text: str, style: str) -> str:
        return paint(text, style, on=self.terminal.color)


# --- the AI advice, for a terminal -------------------------------------------------------------


def advice_lines(report: ReportView, *, width: int, color: bool) -> list[str]:
    """The AI agents' advice in a report, readable in a terminal."""
    advice = report.advice
    if advice is None:
        if report.advice_note:
            return textwrap.wrap(report.advice_note, width=width)
        return ["Nobody has asked the AI agents about this scan yet: choose 1."]
    lines = [
        paint(
            f"AI advice from {advice.model or 'an AI model'}: the policy decided, not the AI.",
            BOLD,
            on=color,
        )
    ]
    for name, status in advice.agents.items():
        if status.status != "ok":
            text = f"The {name} agent: {status.status}" + (
                f". {status.note}" if status.note else "."
            )
            lines += textwrap.wrap(text, width=width)
    places: dict[str, object] = {}
    for finding in report.findings:
        places.setdefault(finding.id, finding)
    if advice.triage:
        lines += ["", paint("Triage", BOLD, on=color)]
        for note in advice.triage:
            finding = places.get(note.finding)
            where = f"{finding.location} {finding.masked_value}" if finding else note.finding
            verdict = VERDICT_WORDS.get(note.verdict, note.verdict)
            lines.append(f"{where}: {verdict}, {note.confidence} confidence.")
            lines += _indented(f"{note.why} Next: {note.next_step}", width)
    if advice.fixes:
        lines += ["", paint("Suggested fixes", BOLD, on=color)]
        for fix in advice.fixes:
            finding = places.get(fix.finding)
            where = finding.location if finding else fix.finding
            needs = f" (needs {fix.import_line})" if fix.import_line else ""
            lines.append(f"{where}: read {fix.env_var} from the environment{needs}.")
            lines.append(f"    {fix.replacement}")
            lines += _indented(fix.why, width)
    if advice.incident:
        plan = advice.incident
        lines += ["", paint(f"Incident plan ({plan.severity})", BOLD, on=color)]
        lines += textwrap.wrap(plan.exposure, width=width)
        for number, step in enumerate(plan.steps, start=1):
            lines += textwrap.wrap(
                f"{number}. {step.title}: {step.detail}", width=width, subsequent_indent="   "
            )
        lines += textwrap.wrap(f"Who to tell: {plan.notify}", width=width)
    return lines


def _indented(text: str, width: int) -> list[str]:
    return textwrap.wrap(text, width=width, initial_indent="    ", subsequent_indent="    ")


# --- the pull request comment, for a terminal ------------------------------------------------

_CODE = re.compile(r"`([^`]*)`")
_STRONG = re.compile(r"\*\*([^*]+)\*\*")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CELL_EDGE = re.compile(r"(?<!\\)\|")  # `safe` writes a pipe inside a cell as \|
_ENTITIES = (("\\|", "|"), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"))


def terminal_lines(markdown: str, *, width: int, color: bool) -> list[str]:
    """SecureGate's pull request comment, readable in a terminal: headings stand out, the
    checklist keeps its boxes, a scanner that did not run is red, and the hidden marker and the
    HTML around the folded list are left out. Text wraps at `width` without splitting a path or
    a masked value; a table is shown in columns (see _table)."""
    lines: list[str] = []
    table: list[str] = []
    caution = False
    for raw in markdown.splitlines():
        line = _CONTROL.sub("", raw).rstrip()
        if line.startswith("|"):
            table.append(line)
            continue
        lines += _table(table, width=width, color=color)
        table = []
        if line.strip() == MARKER or line in ("<details>", "</details>"):
            continue
        if line == "> [!CAUTION]":
            caution = True
            continue
        style, indent = "", ""
        if line.startswith("#"):
            line, style = line.lstrip("#").strip(), BOLD
        elif line.startswith("<summary>") and line.endswith("</summary>"):
            line, style = line[len("<summary>") : -len("</summary>")], BOLD
        elif line.startswith("> "):
            line = f"CAUTION: {line[2:]}" if caution else line[2:]
            style = BOLD + RED if caution else ""
            caution = False
        elif bullet := re.match(r"- (\[ \] )?", line):
            indent = " " * bullet.end()
        pieces = textwrap.wrap(
            _plain(line),
            width=width,
            subsequent_indent=indent,
            break_long_words=False,
            break_on_hyphens=False,
        )
        lines += [paint(piece, style, on=color) for piece in pieces] or [""]
    return lines + _table(table, width=width, color=color)


def _table(rows: list[str], *, width: int, color: bool) -> list[str]:
    """A Markdown table in aligned columns, its header in bold. When the columns would be wider
    than `width`, each row stays as written instead, so no row is ever cut. The |---| line
    under the header is left out either way."""
    rows = [row for row in rows if re.sub(r"[|:\s-]", "", row)]
    cells = [[_plain(cell.strip()) for cell in _CELL_EDGE.split(row)[1:-1]] for row in rows]
    if not rows or len({len(row) for row in cells}) > 1:
        return [_plain(row) for row in rows]
    widths = [max(map(len, column)) for column in zip(*cells, strict=True)]
    if sum(widths) + 2 * (len(widths) - 1) > width:
        return [_plain(row) for row in rows]
    aligned = [
        "  ".join(cell.ljust(size) for cell, size in zip(row, widths, strict=True)).rstrip()
        for row in cells
    ]
    return [paint(aligned[0], BOLD, on=color), *aligned[1:]]


def _plain(text: str) -> str:
    """Markdown marks out, the text in: `code` and **bold** lose their marks, and the escapes
    SecureGate writes (\\| and the HTML entities) become their characters again."""
    text = _STRONG.sub(r"\1", _CODE.sub(r"\1", text))
    for entity, character in _ENTITIES:
        text = text.replace(entity, character)
    return text
