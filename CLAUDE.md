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
   pre-commit, Markdown (dev) and setuptools (build backend).

Test convention: never put a raw fake secret inside an `assert` (pytest prints the operands);
compare masked values, counts or booleans instead.

## Commands
- `make setup`; `make check` (lint + test, before every commit); `make test`; `make lint`
- `make demo` + `make scan-demo`: demo repo in ../securegate-demo; exit 1 is expected there
- `securegate scan --scanners all` adds TruffleHog (required: if it fails, exit 2) to Gitleaks;
  tests run it only with `--no-verification`, so fake keys are never sent to providers
- `make ui`: read-only dashboard (127.0.0.1, masked values, no JavaScript; dark, light in print;
  design values only in src/securegate/ui/static/css/tokens.css). Downloads (CSV/JSON/Markdown)
  and /report are built from the checked ReportView only. `make sample-report`: sample_findings.json
- `make hooks`: laptop gate (pre-commit). Merge gate: .github/workflows/secret-gate.yml
- `securegate demo-token`: fake ACME token for demo pull requests only; never merge one
- `make menu` (`securegate menu`): the interactive menu in src/securegate/menu/ (art, colour only in
  a real terminal). Each choice runs a securegate command; Enter closes its dashboard. Q = exit 0
- `Start SecureGate.cmd`: double-click launcher (setup if asked, `securegate version`, then
  `securegate menu`). ASCII, CRLF; tests/test_launcher.py checks every securegate command in it
  still parses

## Environment
- Gitleaks 8.30.1 (winget). Use only flags listed by `gitleaks git --help` / `gitleaks dir --help`.
- TruffleHog 3.97.9, Semgrep 1.179.0, Bandit 1.9.4: `make scanners` installs them into .venv at the
  versions pinned in the workflow's top `env:` block (tools/install_scanners.py reads them there).
  Use only flags their `--help` lists. gh 2.102.0 (winget).
- Python 3.12.10 in .venv, GNU Make 4.4.1 (winget ezwinports.make), Git 2.55, Windows 11.
- actionlint 1.7.12 (winget) for the workflow; headless Edge builds the PDFs.

When behavior changes, update the matching docs/ page in the same commit, then run
`make docs-pdf` (a test fails when docs/pdf/ is out of date).
