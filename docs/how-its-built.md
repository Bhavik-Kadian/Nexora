# How it's built

A map of SecureGate's files. You don't need to read code to change its behavior: the last table says which file to edit.

## Folders

```
policy.yaml          the rules that decide block / warn / ignore
.gitleaks.toml       which key shapes Gitleaks looks for
Makefile             short commands: make setup, make test, make demo, ...
src/securegate/      the program
tests/               automatic checks that prove the program works
docs/                these pages
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
| `report.py` | Prints the table and writes `findings.json`. |
| `demo/` | Builds the demo repo: `catalog.yaml` (what to plant), `generator.py`, `scorecard.py`. |
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
| detect a new kind of key | `.gitleaks.toml`: add a `[[rules]]` entry, like `acme-pay-token` |
| plant a new secret or decoy in the demo | `src/securegate/demo/catalog.yaml` (see [Testing](testing.md)) |
| change how values are masked | `src/securegate/mask.py` |
| change the table or `findings.json` | `src/securegate/report.py` |
| change the confidence score | `src/securegate/confidence.py` |

When you change a behavior, update the matching page in `docs/` in the same commit.
