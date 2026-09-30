# SecureGate: notes for Claude

SecureGate v0.1 is a secret-scanning gate for Git repos: Gitleaks finds secrets, `policy.yaml`
decides (block / warn / ignore), and reports show secrets masked. The plan is in PLAN.md.

## Non-negotiable rules
1. Never print, log, store or write a full secret anywhere: not in findings, reports, logs,
   exceptions or test output. Findings hold only a masked value and a fingerprint.
2. No key-shaped strings in any committed file, including tests and fixtures. Build fake keys at
   runtime (prefix + random characters); build markers like PEM headers from parts at runtime too.
   If our own scanner flags our own source, fix the code; never allowlist our own source files.
3. Demo repos go outside this repo (default ../securegate-demo) or into a pytest tmp_path. The
   generator refuses a non-empty folder unless --force, and never deletes outside its output folder.
4. Only the policy engine decides. Exit codes: 0 = pass, 1 = at least one "block", 2 = tool error
   (missing Gitleaks, bad config, unreadable report). Errors fail closed: never exit 0 on an error.
5. Small modules, type hints, pure functions where possible. The Gitleaks runner is injected so
   tests can fake it.
6. Ask before adding any dependency beyond PyYAML, Jinja2, Flask (runtime), pytest, ruff,
   pre-commit (dev) and setuptools (build backend).

Test convention: never put a raw fake secret inside an `assert` (pytest prints the operands);
compare masked values, counts or booleans instead.

## Commands
- `make setup`: create .venv on Python 3.12 and install with dev extras
- `make test` / `make lint` / `make check` (lint + test; run before every commit)
- `make demo`: build the demo repo in ../securegate-demo (from src/securegate/demo/catalog.yaml)
- `make scan-demo`: scan it; SecureGate exits 1 because blocked findings are expected
- `make ui`: read-only dashboard on the demo scan (127.0.0.1 only, masked values, no JavaScript;
  design values only in src/securegate/ui/static/css/tokens.css)
- `make sample-report`: write sample_findings.json (about 20 findings) for the designers

## Environment
- Gitleaks 8.30.1 (winget). Use only flags listed by `gitleaks git --help` / `gitleaks dir --help`.
- Python 3.12.10 in .venv, GNU Make 4.4.1 (winget ezwinports.make), Git 2.55, Windows 11.

When behavior changes, update the matching docs/ page in the same commit.
