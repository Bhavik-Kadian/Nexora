# Plan: double-click opens SecureGate itself (interactive menu + terminal art)

> **Working note, kept as it was written.** The approved plan for `Start SecureGate.cmd` opening SecureGate's own menu. Written on 2026-10-03. Built the same day. The pages in [docs/](../README.md) describe SecureGate as it is; [History](README.md) lists every note.

## Context

Right now, double-clicking `Start SecureGate.cmd` does one fixed job: it builds the demo, scans it
and then just keeps the window open while the dashboard runs. You want the double-click to open
**SecureGate itself**, like an app, with good terminal art on launch.

Your choices: an **interactive menu**, and **the padlock + big letters** art.

The result: double-click, and the window shows a gold padlock and big SECUREGATE letters that fade
from cyan to blue. Below them you see a status block and a numbered menu. You pick a number and press
Enter. Q closes the window. The menu runs the same `securegate` commands you would type, so exit codes,
masking and fail-closed behavior stay exactly as they are.

```
  ▄█▀▀▀█▄    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗  █████╗ ████████╗███████╗
  █     █    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
███████████  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ███╗███████║   ██║   █████╗
████   ████  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║   ██║██╔══██║   ██║   ██╔══╝
█████ █████  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╔╝██║  ██║   ██║   ███████╗
▀█████████▀  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
             Finds secrets in a Git project, masks them, and blocks the dangerous ones.

  Setup       SecureGate 0.1.0, Gitleaks 8.30.1, rules in policy.yaml
  Demo        ready in ..\securegate-demo
  Last scan   findings-demo.json: BLOCKED (6 block, 4 warn, 1 ignore)

  What do you want to do?

    1  Scan the demo project     its whole history (built the first time)
    2  Scan a project of yours   type its folder, or drag it in here
    3  Open the dashboard        the last scan, in your browser
    4  Show the rules            what policy.yaml blocks, warns and ignores
    5  Rebuild the demo project  start it over, exactly as new
    6  Check the setup           versions, rules and the laptop gate
    Q  Quit

  Type a number and press Enter: _
```

This screen is about 25 lines tall and fits this laptop's 120×30 console.

## New command: `securegate menu` (also `make menu`)

New package **`src/securegate/menu/`**, laid out like `ui/`. Every module is small and typed, and
the screen text comes from pure functions:

- **`art.py`**: the artwork as plain text.
  - The padlock (6 rows), plus a letter dictionary for the big block letters, the slim pixel
    letters and ASCII letters.
  - `banner_lines(width, unicode)` picks the biggest version that fits the window:
    - padlock + big letters: 96 columns
    - big letters alone: 83 columns
    - padlock + slim letters: about 52 columns
    - slim letters alone: 39 columns
    - ASCII letters, when the output can't show block characters (a pipe, a legacy code page).
- **`terminal.py`**: the terminal itself.
  - A `Terminal` dataclass (ask, say, columns, color, unicode, sleep) that tests replace.
  - `real_terminal()`, `wants_color()` and `paint()`.
  - Colour only when stdout is a real terminal, never when `NO_COLOR` is set or `TERM=dumb`.
  - On Windows it turns on ANSI codes with `ctypes` (`SetConsoleMode` with
    ENABLE_VIRTUAL_TERMINAL_PROCESSING). If that fails, the screen stays plain.
  - The art uses 24-bit colour: a gold padlock, letters fading from cyan to blue by row, and a grey
    3D shadow. All other text uses the 16 theme colours, so it stays readable on light themes too.
  - The banner appears line by line (about 0.25 s), only the first time and only in a real terminal.
- **`app.py`**: `run_menu(terminal, *, run_command, open_dashboard, gitleaks_version) -> int`.
  - After each choice: "Press Enter to go back to the menu". The screen then clears and redraws.
  - Before running a command, the menu prints it dimmed, for example
    `> securegate scan ..\securegate-demo --mode repo --out findings-demo.json`, so you can see
    the command it types for you.
  - **Status block**: versions (Gitleaks is looked up once), whether `policy.yaml` is here, whether
    the demo is ready (the `.securegate-demo` marker, `demo.generator.MARKER_FILE`), and the last
    scan. The last scan is read through `ui.report_view.load_report`, which only ever passes masked
    values.
  - **1 Scan the demo**:
    - builds it first if it is missing (`demo-repo --out ../securegate-demo --seed 42 --force`)
    - then runs `scan ../securegate-demo --mode repo --out findings-demo.json`
    - on exit code 1, says that is the expected result
    - on 0 or 1, asks "Open the results in the dashboard? [Y/n]"
    - on any other code, says the scan failed and never offers the dashboard.
  - **2 Scan a project of yours**:
    - takes a typed or dragged-in path (surrounding quotes are removed) and resolves it to a full path
    - if nothing is there, it says so
    - a folder with `.git` asks "whole Git history? [Y/n]" (`repo`, or `dir` if you answer n);
      a plain folder is scanned as `dir`
    - writes `findings.json`, then offers the dashboard the same way.
  - **3 Open the dashboard**: opens the last report of this session (`findings-demo.json` to start
    with). If there is none, it tells you to choose 1 first.
  - **4 Show the rules**: `load_policy("policy.yaml")`, then each rule in order with its name, a
    BLOCK / WARN / IGNORE word (coloured, never colour alone) and its reason, wrapped to the window.
    It ends with how to change them (`notepad policy.yaml`).
  - **5 Rebuild the demo**: asks "[y/N]" first, then runs `demo-repo ... --force`.
  - **6 Check the setup**: runs `version`, then shows whether `policy.yaml` loads (and how many
    rules), whether the laptop gate is on (`.git\hooks\pre-commit`; if not, "turn it on with:
    make hooks"), and whether the demo is ready.
  - **Q**: exit code 0. An unknown key shows a hint under the menu.
  - **Input that ends** (EOFError): the menu stops with a `SecureGateError`, so you get exit code 2 and
    `securegate: error: ...`. Ctrl+C at the menu gives exit code 2 too (the CLI's existing rule).
    Ctrl+C during a scan only stops that scan, because the nested `main()` catches it. The menu goes on.

**`cli.py`**:
- `commands.add_parser("menu", ...)` and `if args.command == "menu": return _menu(runner)`.
- `_menu` imports the menu lazily, the way `_ui` loads Flask lazily. It wires:
  - `run_command`: `main(argv, runner=runner)`, inside a small wrapper that turns an argparse
    `SystemExit` into its code, so a bad argument can never kill the menu
  - `open_dashboard`: `serve(report, port=DASHBOARD_PORT, open_browser=True, wait=...)`, with
    Werkzeug's per-page log lines turned off for the menu
  - `gitleaks_version(runner)`.
- New `DASHBOARD_PORT = 5000`, also used as the default of `ui --port`.

**`ui/server.py`**: `serve()` gets an optional `wait: Callable[[], object] | None`.
- With `wait`, the server runs in a daemon thread. The menu shows "Press Enter to close the
  dashboard and go back to the menu" while `wait()` blocks.
- When `wait()` returns, `try/finally` calls `server.shutdown()` and `join()`, then `server_close()`.
  This also happens if `wait()` raises.
- Without `wait`, nothing changes (`make ui` still stops with Ctrl+C).
- Enter instead of Ctrl+C also avoids cmd.exe's "Terminate batch job (Y/N)?" prompt.

## Launcher: `Start SecureGate.cmd` (still ASCII + CRLF)

The steps become: the location check → setup if missing (asks first) → `"%PYTHON%" -m securegate
version || goto :failed` (the broken-.venv hint stays) → `"%PYTHON%" -m securegate menu || goto
:failed` → `exit /b 0`.

- The demo build, scan, dashboard step and the old dashboard hint move into the menu.
- Q closes the window. A menu that stops with an error keeps the window open with
  "SecureGate stopped" and a pause.
- The header comment explains the new flow.

## Rules this plan follows (CLAUDE.md)

- **Rule 1 (no full secret anywhere):** the menu prints only what the existing commands print,
  plus `load_report` summaries. It does not offer `demo-token`.
- **Rule 2 (no key-shaped strings):** the art is block and box characters with no key-like
  names. The self-scan test checks this.
- **Rule 3 (demo outside the repo):** the demo stays in `../securegate-demo`.
- **Rule 4 (exit codes):** unchanged. The menu never turns a failed scan into a pass.
- **Rule 6 (dependencies):** nothing new. The menu uses only the standard library (ANSI codes, `ctypes`), not Rich or Textual.

I checked that ruff accepts the block and box characters as they are, so no lint exemption is needed.

## Tests

**`tests/test_menu.py`**: a fake `Terminal` with scripted answers, a recorder `run_command`
that returns chosen exit codes (its `demo-repo` touches the marker, like the launcher's stand-in),
and a recorder `open_dashboard`. It runs in `tmp_path` with `policy.yaml` copied in. It checks:
- Q → 0.
- The first screen shows the art, the status and every option.
- 1 builds the demo the first time only.
- Enter after a scan opens the dashboard on that scan's report; n does not.
- A scan that exits 2 never offers the dashboard.
- 2: a Git folder → `repo`, n → `dir`, a plain folder → `dir`, quotes are stripped, a missing path
  is not scanned.
- 3 with no report says to scan first.
- 5 asks first.
- 6 runs `version` and reports the laptop gate.
- 4 lists the policy rules in order with their decisions.
- An unknown key shows the hint.
- **Every command the menu runs parses** with `build_parser()`.
- **No leak:** with `git` present, the menu really builds the demo (seed 42) and scans it with
  `FakeGitleaks(report=report_for_demo(demo_repo))`. `leaked(planted, output) == []` must hold
  for everything printed.
- `main(["menu"])` with input that ends returns 2 with `securegate: error:`.

**`tests/test_menu_art.py`**:
- Every letter is a rectangle (all rows the same width).
- For widths 40 to 200, every banner line fits.
- At 120 columns you get the padlock + big letters. Without Unicode the banner is ASCII only.
- With colour off there are no escape codes. With colour on, removing them gives back the plain
  text.
- `wants_color` is false for a non-terminal, with `NO_COLOR`, and with `TERM=dumb`.

**`tests/test_ui_server.py`**: a real server with `wait`. `wait()` loads `/` (200) and returns,
`serve` returns 0, and the port is free again.

**`tests/test_launcher.py`**:
- It runs `["version", "menu"]`.
- On Windows (stand-in module, as today):
  - Q (exit 0) closes the window with exit 0
  - menu exit 2 → "SecureGate stopped", exit 1
  - version exit 2 → the "Delete that folder" hint
  - the setup-question, no-Python and copied-elsewhere tests stay.
- The demo-specific launcher tests are dropped, because the menu tests now cover them.

## Docs and project files (same change, per CLAUDE.md)

- `Makefile`: `menu` target, header line, `.PHONY`.
- `CLAUDE.md`: the launcher line ("setup if asked, then `securegate menu`") and `make menu` in
  Commands.
- `docs/README.md`, `docs/getting-started.md` ("The quick way on Windows"), `docs/ui.md`: describe
  the menu. The dashboard is option 3, and Enter closes it.
- `docs/how-its-built.md`:
  - the Folders entry
  - a `menu/` row in Modules
  - "Where to change what" rows for the menu, the art and its colours.
- `docs/presenting-to-judges.md`:
  - the one-click paragraph becomes the menu (double-click, 1, Enter)
  - a `make menu` row in the commands table
  - the 127.0.0.1 sentence, the step 5 tip, "After the demo", the troubleshooting rows (including
    "Terminate batch job (Y/N)?" after Ctrl+C) and "Where everything is"
  - the test counts on lines 110, 367 and 429, using the real numbers from `make check`.
- `docs/decisions.md`: update entry 40, and add **41. The double-click opens a menu**.
  - Chose: a numbered menu, Enter to close the dashboard, colour only in a real terminal with ASCII
    art as the fallback.
  - Rejected: Rich or Textual (a new dependency) and single-key input (Windows-only calls, and
    hard to test).
- Run `make docs-pdf` (a test fails when `docs/pdf/` is out of date).
- Memory: note that the launcher now runs `securegate menu`, so the queued command renames must
  update the menu's commands too.

## Verification

1. `make check`: ruff, plus all tests. That includes the self-scan with the real Gitleaks, the
   launcher run through cmd.exe, and the docs-PDF freshness check.
2. Run the real menu with piped answers:
   `printf '1\nn\n4\n\n6\n\nq\n' | .venv/Scripts/python.exe -m securegate menu`. It must scan
   the demo (exit 1 is shown as expected), list the rules, check the setup, quit with 0, and show
   only masked values. Also check the plain/ASCII path (output is a pipe here).
3. Print the banner at several widths to check the alignment by eye.
4. Then you double-click `Start SecureGate.cmd` and look at the colours and the animation. My tools
   can't see a real console window. Try 1 → Enter (dashboard) → Enter → Q.
5. Nothing is committed until you say so. Then it goes in as one commit, like the earlier ones.
