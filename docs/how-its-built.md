# How it's built

A map of SecureGate's files. You don't need to read code to change its behavior: the last table says which file to edit.

## Folders

```
policy.yaml                         the rules that decide block / warn / ignore
.gitleaks.toml                      which key shapes Gitleaks looks for
.trufflehog.yaml                    TruffleHog's extra detectors (the ACME Pay token)
rules/securegate-risky.yml          SecureGate's own Semgrep rules: risky handling of secrets
.pre-commit-config.yaml             the laptop gate (installed with make hooks)
.github/workflows/secret-gate.yml   the merge gate: the check on every pull request
Makefile                            short commands: make setup, make test, make demo, ...
Start SecureGate.cmd                double-click: open SecureGate's menu
src/securegate/                     the program
tools/                              helpers for the gates and the docs
tests/                              automatic checks that prove the program works
docs/                               these pages
```

## Modules

A **module** is one Python file with one job. When you run a scan, they work in this order:

| Module | Job |
|---|---|
| `cli.py` | Reads your command (`securegate scan ...`), runs it, and returns the exit code. |
| `scanners/gitleaks.py` | Runs Gitleaks, reads its report from a temporary folder, then deletes the folder. |
| `scanners/trufflehog.py` | With `--scanners all`: runs TruffleHog over the Git history. It can ask the provider whether a key still works. |
| `scanners/changes.py` | Copies the code Semgrep and Bandit read into a private folder: in a range scan, the files the range changed, as they are at its end. |
| `scanners/semgrep.py` | Runs Semgrep with p/secrets and SecureGate's own rules on that copy. If it fails, the scan goes on and says Semgrep did not run. |
| `scanners/bandit.py` | Runs Bandit's password checks (B105, B106, B107) on the Python files of that copy. Optional, like Semgrep. |
| `pipeline.py` | The only place raw secrets pass through. It turns each one into a masked finding, then merges findings. |
| `merge.py` | Turns findings of the same secret or line into one, keeping the strongest decision and every scanner that found it. |
| `entropy.py` | Measures how random a value looks. |
| `policy.py` | Reads `policy.yaml` and decides block, warn or ignore. |
| `confidence.py` | Scores from 0 to 1 how sure we are that a finding is a real secret. |
| `mask.py` | Hides the value and makes its fingerprint. |
| `finding.py` | The finding record. It can only hold a masked value. |
| `report.py` | Prints the table, the "why and fix" lines for blocked findings, and writes `findings.json`. |
| `outputs/` | The reports besides `findings.json`: the pull request comment and the job summary (one template, `outputs/templates/report.md.j2`; `securegate summary` prints it), the checklists to rotate a blocked key (`outputs/rotation.py`) and SARIF for GitHub's Security tab (`outputs/sarif.py`). All are made from `findings.json` read back through the dashboard's check that every value is masked. |
| `demo/` | Builds the demo repo: `catalog.yaml` (what to plant), `generator.py`, `scorecard.py`. |
| `ui/` | The read-only dashboard: `app.py` (the pages and downloads), `report_view.py` (reads and checks `findings.json`), `fixes.py` ("How to fix"), `export.py` (the CSV and JSON downloads), `server.py` (127.0.0.1 only, on a port it never shares), `templates/` and `static/css/` (a dark theme, light when printed). |
| `menu/` | The menu that `Start SecureGate.cmd` and `make menu` open: `app.py` (the screen and the choices; each choice runs a `securegate` command and shows it first), `art.py` (the padlock and the big letters) and `terminal.py` (colours, only in a real terminal). |
| `errors.py`, `validate.py`, `programs.py` | Helpers: error types, checks for hand-edited files, finding programs safely. |
| `scanners/common.py`, `scanners/candidate.py` | What the scanner adapters share: running a program, reading its flags, the raw finding. |

## The Finding format

Each entry in `findings.json` is one finding. This real example comes from scanning the demo repo:

| Field | Example | Meaning |
|---|---|---|
| id | `dcc7b5bbfe3c` | Short name: the first 12 characters of the fingerprint. The same secret always gets the same id. |
| rule | `stripe-access-token` | The scanner rule that matched. |
| detector | `gitleaks` | The scanner that found it first. |
| detectors | `gitleaks`, `trufflehog` | Every scanner that found it. |
| file | `scripts/migrate_customers.py` | Where, relative to the scanned folder. |
| line | `3` | The line where the value starts. |
| commit | `720d024c...` | The commit that added it. Empty (null) when only files on disk were scanned. |
| author | `Riya Demo` | Who made that commit. |
| date | `2025-06-04T09:00:00Z` | When. |
| masked_value | `sk_l****562d` | The value with all but 4 + 4 characters hidden. |
| fingerprint | `dcc7b5bb...` (64 characters) | Recognizes the same secret again. It cannot be turned back into the secret. |
| entropy | `4.625` | How random the value looks (random keys: about 4 to 6). |
| confidence | `0.9` | 0 to 1: how sure we are that it is a real secret. |
| validity | `not_checked` | Is the key live? `verified` (the provider confirmed it works), `unknown` (the check failed), `unverified` (not confirmed) or `not_checked`. Only TruffleHog checks. |
| severity | `high` | critical, high, medium, low or info, from the policy. |
| decision | `block` | block, warn or ignore, from the policy. |
| matched_rule | `rule 8: provider-keys` | The policy rule that decided, with its number. |
| reason | `provider-keys: A payment, cloud or ...` | Which policy rule decided, and why. |
| remediation | `Treat it as leaked. Rotate ...` | What to do next. |

The file also has a summary at the top: status (pass, fail or error), exit code, Gitleaks version, which scanners ran and counts per decision. After an error it has no findings list at all, so nobody can mistake a failed scan for a clean one.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass. Nothing to block (there may be warnings). |
| 1 | At least one finding is "block". |
| 2 | SecureGate could not do its job: Gitleaks missing, a broken `policy.yaml`, an unreadable report. It never says "pass" when something went wrong. |

## Where to change what

| I want to... | Change this |
|---|---|
| block, warn or ignore a kind of finding | `policy.yaml`: add or move a rule |
| treat a folder differently | `policy.yaml`: `path_matches` |
| ignore a known fake value | `policy.yaml`: `value_matches` in the `placeholders` rule |
| change the "why" or "fix" line shown for a blocked finding | `policy.yaml`: `reason` and `remediation` of that rule |
| detect a new kind of key | `.gitleaks.toml`: add a `[[rules]]` entry, like `acme-pay-token`; for TruffleHog too, `.trufflehog.yaml` |
| install TruffleHog, Semgrep and Bandit, or change their versions | `make scanners`; the versions are in the `env:` block at the top of `.github/workflows/secret-gate.yml` |
| change how findings of the same line are merged | `src/securegate/merge.py` |
| change the pull request comment or the job summary | `src/securegate/outputs/templates/report.md.j2` |
| change the steps to rotate a blocked key | `src/securegate/outputs/rotation.py` |
| change the SARIF file for GitHub's Security tab | `src/securegate/outputs/sarif.py` |
| catch another risky way of handling a secret | `rules/securegate-risky.yml` (and its sample in `tests/test_code_scanners_real.py`) |
| plant a new secret or decoy in the demo | `src/securegate/demo/catalog.yaml` (see [Testing](testing.md)) |
| change how values are masked | `src/securegate/mask.py` |
| change the table or `findings.json` | `src/securegate/report.py` |
| change the confidence score | `src/securegate/confidence.py` |
| change the dashboard's colours, fonts or spacing, on screen or on paper | `src/securegate/ui/static/css/tokens.css` (see [Dashboard](ui.md)) |
| change what a dashboard page shows | `src/securegate/ui/templates/` |
| change the columns of the CSV download, or the JSON download | `src/securegate/ui/export.py` |
| change the "How to fix" advice | `src/securegate/ui/fixes.py` |
| change what the check on pull requests does | `.github/workflows/secret-gate.yml` (see [The two gates](merge-gate.md)) |
| change the check before each commit | `.pre-commit-config.yaml` and `tools/precommit_hook.py` |
| change the menu's choices, or what they run | `src/securegate/menu/app.py` (`tests/test_menu.py` checks that every command it runs exists) |
| change the art on the menu's first screen, or its colours | `src/securegate/menu/art.py` |
| change what double-clicking `Start SecureGate.cmd` does before the menu opens | `Start SecureGate.cmd` (a Windows batch file; `tests/test_launcher.py` checks the commands it runs) |
| update the PDF copies of these pages | edit the `.md` page, then run `make docs-pdf` (`tools/docs_pdf.py`) |

When you change a behavior, update the matching page in `docs/` in the same commit, and run `make docs-pdf` so its PDF matches. A test fails when a PDF is out of date.
