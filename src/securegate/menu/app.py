"""The menu that Start SecureGate.cmd opens: SecureGate without typing commands.

Each choice runs the securegate commands a person would type, through `run_command`, and shows
each command before running it. So the exit codes, masking and fail-closed checks are exactly
those of the CLI. Apart from that, the menu only reads: policy.yaml for the rules, and the last
report through the dashboard's loader, which refuses any value that is not masked.
"""

import textwrap
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from securegate import __version__
from securegate.demo.generator import MARKER_FILE
from securegate.errors import SecureGateError
from securegate.finding import DECISIONS
from securegate.menu.art import TAGLINE, banner, render
from securegate.menu.terminal import BOLD, CLEAR, CYAN, GREEN, GREY, RED, YELLOW, Terminal, paint
from securegate.policy import load_policy
from securegate.ui.report_view import ReportView, load_report

EXIT_PASS = 0  # securegate's exit codes, as in cli.py
EXIT_BLOCK = 1

DEMO_DIR = Path("../securegate-demo")  # where make demo builds it, next to the SecureGate folder
DEMO_SEED = "42"
DEMO_REPORT = Path("findings-demo.json")
OWN_REPORT = Path("findings.json")
POLICY = Path("policy.yaml")
LAPTOP_GATE = Path(".git/hooks/pre-commit")  # what make hooks installs
MARGIN = "  "
REVEAL_SECONDS = 0.04  # between the lines of the art, on the first screen only

CHOICES = (
    ("1", "Scan the demo project", "its whole history (built the first time)"),
    ("2", "Scan a project of yours", "type its folder, or drag it in here"),
    ("3", "Open the dashboard", "the last scan, in your browser"),
    ("4", "Show the rules", "what policy.yaml blocks, warns and ignores"),
    ("5", "Rebuild the demo project", "start it over, exactly as new"),
    ("6", "Check the setup", "versions, rules and the laptop gate"),
    ("Q", "Quit", ""),
)
QUIT = ("q", "quit", "exit")
DECISION_STYLES = {"block": BOLD + RED, "warn": BOLD + YELLOW, "ignore": GREY}
RESULT_STYLES = {"PASS": BOLD + GREEN, "BLOCKED": BOLD + RED}

RunCommand = Callable[[Sequence[str]], int]
OpenDashboard = Callable[[Path, Callable[[], object]], object]


class InputEnded(SecureGateError):
    """Nobody can answer the menu any more: its input ended."""


def run_menu(
    terminal: Terminal,
    *,
    run_command: RunCommand,
    open_dashboard: OpenDashboard,
    gitleaks_version: str | None,
) -> int:
    """Show the menu until the person chooses Q, then return exit code 0.

    `run_command` runs one securegate command and returns its exit code. `open_dashboard`
    shows a report in the dashboard until the function it is given returns.
    """
    return Menu(terminal, run_command, open_dashboard, gitleaks_version).run()


@dataclass
class Menu:
    terminal: Terminal
    run_command: RunCommand
    open_dashboard: OpenDashboard
    gitleaks_version: str | None  # None: Gitleaks was not found
    last_report: Path = DEMO_REPORT  # the report the dashboard opens
    hint: str = ""  # shown under the choices on the next screen

    def run(self) -> int:
        actions: dict[str, Callable[[], bool]] = {
            "1": self.scan_demo,
            "2": self.scan_project,
            "3": self.dashboard,
            "4": self.rules,
            "5": self.rebuild_demo,
            "6": self.check_setup,
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
                self.hint = "Type a number from 1 to 6, or Q to quit, then press Enter."
                continue
            self.say("")
            try:
                wait = action()  # True: keep the result on screen until Enter
            except InputEnded:
                raise
            except SecureGateError as err:
                self.say(f"securegate: error: {err}")
                wait = True
            if wait:
                self.ask(f"\n{MARGIN}Press Enter to go back to the menu. ")

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
            shown = self.paint(key, BOLD + CYAN)
            self.say(f"{MARGIN}  {shown}  {label:<26}{self.paint(note, GREY)}".rstrip())
        self.say("")
        if self.hint:
            self.say(MARGIN + self.paint(self.hint, YELLOW))

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
            ("Demo", self.demo_status()),
            ("Last scan", self.last_scan()),
        ]

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
        self.say("")
        code = self.securegate("scan", str(target), "--mode", mode, "--out", str(OWN_REPORT))
        return self.after_scan(code, OWN_REPORT)

    def after_scan(self, code: int, report: Path) -> bool:
        """After a finished scan, offer the dashboard. After a failed one, never: it would only
        show that the scan failed."""
        self.last_report = report
        if code not in (EXIT_PASS, EXIT_BLOCK):
            self.tell(self.paint("The scan failed: the lines above say why.", RED))
            return True
        self.say("")
        if not self.yes("Open the results in the dashboard? [Y/n] ", default=True):
            return False
        return self.show_dashboard(report)

    def dashboard(self) -> bool:
        if not self.last_report.is_file():
            self.tell(
                f"There is no scan report yet ({self.last_report}). "
                "Choose 1 to scan the demo project first."
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
