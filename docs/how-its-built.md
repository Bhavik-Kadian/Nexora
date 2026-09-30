# How it's built

A map of SecureGate's files. You don't need to read code to change its behavior: the last table says which file to edit.

## Folders

```
policy.yaml                         the rules that decide block / warn / ignore
.gitleaks.toml                      which key shapes Gitleaks looks for
.pre-commit-config.yaml             the laptop gate (installed with make hooks)
.github/workflows/secret-gate.yml   the merge gate: the check on every pull request
Makefile                            short commands: make setup, make test, make demo, ...
Start SecureGate.cmd                double-click: build the demo, scan it, open the dashboard
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
| `pipeline.py` | The only place raw secrets pass through. It turns each one into a masked finding. |
| `entropy.py` | Measures how random a value looks. |
| `policy.py` | Reads `policy.yaml` and decides block, warn or ignore. |
| `confidence.py` | Scores from 0 to 1 how sure we are that a finding is a real secret. |
| `mask.py` | Hides the value and makes its fingerprint. |
| `finding.py` | The finding record. It can only hold a masked value. |
| `report.py` | Prints the table, the "why and fix" lines for blocked findings, and writes `findings.json`. |
| `summary.py` | Turns `findings.json` into a short Markdown summary (`securegate summary`), used on GitHub's check page. |
| `demo/` | Builds the demo repo: `catalog.yaml` (what to plant), `generator.py`, `scorecard.py`. |
| `ui/` | The read-only dashboard: `app.py` (the pages), `report_view.py` (reads and checks `findings.json`), `fixes.py` ("How to fix"), `server.py` (127.0.0.1 only), `templates/` and `static/css/`. |
| `errors.py`, `validate.py`, `programs.py` | Helpers: error types, checks for hand-edited files, finding programs safely. |

## The Finding format

Each entry in `findings.json` is one finding. This real example comes from scanning the demo repo:

| Field | Example | Meaning |
|---|---|---|
| id | `dcc7b5bbfe3c` | Short name: the first 12 characters of the fingerprint. The same secret always gets the same id. |
| rule | `stripe-access-token` | The Gitleaks rule that matched. |
| detector | `gitleaks` | The scanner that found it. |
| file | `scripts/migrate_customers.py` | Where, relative to the scanned folder. |
| line | `3` | The line where the value starts. |
| commit | `720d024c...` | The commit that added it. Empty (null) when only files on disk were scanned. |
| author | `Riya Demo` | Who made that commit. |
| date | `2025-06-04T09:00:00Z` | When. |
| masked_value | `sk_l****562d` | The value with all but 4 + 4 characters hidden. |
| fingerprint | `dcc7b5bb...` (64 characters) | Recognizes the same secret again. It cannot be turned back into the secret. |
| entropy | `4.625` | How random the value looks (random keys: about 4 to 6). |
| confidence | `0.9` | 0 to 1: how sure we are that it is a real secret. |
| severity | `critical` | critical, high, medium, low or info, from the policy. |
| decision | `block` | block, warn or ignore, from the policy. |
| reason | `provider-keys: A payment, cloud or ...` | Which policy rule decided, and why. |
| remediation | `Treat it as leaked. Rotate ...` | What to do next. |

The file also has a summary at the top: status (pass, fail or error), exit code, Gitleaks version and counts per decision. After an error it has no findings list at all, so nobody can mistake a failed scan for a clean one.

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
| detect a new kind of key | `.gitleaks.toml`: add a `[[rules]]` entry, like `acme-pay-token` |
| plant a new secret or decoy in the demo | `src/securegate/demo/catalog.yaml` (see [Testing](testing.md)) |
| change how values are masked | `src/securegate/mask.py` |
| change the table or `findings.json` | `src/securegate/report.py` |
| change the confidence score | `src/securegate/confidence.py` |
| change the dashboard's colours, fonts or spacing | `src/securegate/ui/static/css/tokens.css` (see [Dashboard](ui.md)) |
| change what a dashboard page shows | `src/securegate/ui/templates/` |
| change the "How to fix" advice | `src/securegate/ui/fixes.py` |
| change what the check on pull requests does | `.github/workflows/secret-gate.yml` (see [The two gates](merge-gate.md)) |
| change the check before each commit | `.pre-commit-config.yaml` and `tools/precommit_hook.py` |
| change what double-clicking `Start SecureGate.cmd` does | `Start SecureGate.cmd` (a Windows batch file; `tests/test_launcher.py` checks the commands it runs) |
| update the PDF copies of these pages | edit the `.md` page, then run `make docs-pdf` (`tools/docs_pdf.py`) |

When you change a behavior, update the matching page in `docs/` in the same commit, and run `make docs-pdf` so its PDF matches. A test fails when a PDF is out of date.
