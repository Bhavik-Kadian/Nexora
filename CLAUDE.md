# SecureGate: notes for Claude

SecureGate v0.1 is a secret-scanning gate for Git repos: Gitleaks finds secrets, `policy.yaml`
decides (block / warn / ignore), and reports show secrets masked. The original plan and the working
notes are in docs/history/; docs/roadmap.md lists what was never built.

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
- `securegate scan --scanners all` adds TruffleHog (required: if it fails, exit 2), Semgrep and
  Bandit (optional: if one fails, the scan goes on and records "did not run"); tests run
  TruffleHog only with `--no-verification`, so fake keys are never sent to providers.
  `--comment/--summary/--sarif FILE` are built from findings.json read back through
  load_report (masked only); no SARIF is written after an error
- `make ui`: read-only dashboard (127.0.0.1, masked values, no JavaScript; dark, light in print;
  design values only in src/securegate/ui/static/css/tokens.css). Downloads (CSV/JSON/Markdown)
  and /report are built from the checked ReportView only. `make sample-report`: sample_findings.json
- `make hooks`: laptop gate (pre-commit). Merge gate: .github/workflows/secret-gate.yml (all four
  scanners on every PR to main; summary, one PR comment, SARIF, findings.json artifact). It installs
  SecureGate and its rules from the BASE branch, so a gate change ships in two PRs: code, then the
  workflow that uses it. After the scan, a continue-on-error step runs `securegate agents` (secret
  SECUREGATE_AI_KEY, vars SECUREGATE_AI_ENDPOINT/DEPLOYMENT); it never decides. action.yml is
  the same gate as a composite action for other repos (docs/install.md): SecureGate from the
  action's tag, the policy from the caller's base branch; tests/test_action.py keeps its pins,
  install scripts and comment script equal to the workflow's. Repos: origin = Bhavik-Kadian/Nexora
  (renamed from SecureGate at the close-out; old links redirect), backup = Bhavik-Kadian/
  Nexora-backup (the old Nexora repo: copies of early branches; leave it alone). Release v1.0.0.
  main has the ruleset "Protect main" (PR + secret-gate check required, empty bypass list), so
  every change, docs too, reaches main through a pull request
- `securegate demo-token`: fake ACME token for demo pull requests only; never merge one
- `make demo-clean|demo-leak|demo-deleted|demo-decoys|demo-risky` (`securegate demo-pr`): a demo PR on
  origin, built in a temp worktree from origin/main (clean tree + gh login needed; only demo/
  branches). `make demo-cleanup` closes them all; `make doctor` checks readiness; `make ci-report`
- `securegate agents --report F`: triage/fix/incident AI agents (agents/, Azure AI Foundry, stdlib
  HTTPS; advice in the report's "advice" section, re-checked on load; never changes decisions).
  `ai-setup` writes .securegate/ai.json, `ai-check`/doctor test it. Tests never call Azure
  (conftest patches cli._azure_model); the redaction leak tests must stay green.
  `agent-fix --pr N` (menu 9 then F): fix PR into that PR's branch; SecureGate edits the literal
- `make menu` (`securegate menu`): the interactive menu in src/securegate/menu/ (art, colour only in
  a real terminal). Each choice runs a securegate command; Enter closes its dashboard. Q = exit 0.
  2 = `make scan-demo-all` (a test compares them), then the PR comment in the terminal; 3 shows it;
  9 = merge gate screen: demo PRs (link from reports/demo-pr.json), `ci-report --pr N --wait`, cleanup, doctor;
  A = AI agents screen (ask, show, dashboard, ai-setup, ai-check); 9 then F = agent-fix
- `Start SecureGate.cmd`: double-click launcher (setup if asked, `securegate version`, then
  `securegate menu`). ASCII, CRLF; tests/test_launcher.py checks every securegate command in it
  still parses

## Environment
- Tool versions are pinned once, in the workflow's top `env:` block, and repeated in action.yml
  and here (tests check they match): Gitleaks 8.30.1 (winget), TruffleHog 3.97.9, Semgrep 1.179.0, Bandit 1.9.4
  (`make scanners` installs the last three into .venv; tools/install_scanners.py reads the block).
  Use only flags each tool's `--help` lists. gh 2.102.0 (winget).
- Python 3.12.10 in .venv, GNU Make 4.4.1 (winget ezwinports.make), Git 2.55, Windows 11.
- actionlint 1.7.12 (winget) for the workflow; headless Edge builds the PDFs.

When behavior changes, update the matching docs/ page in the same commit, then run
`make docs-pdf` (a test fails when docs/pdf/ is out of date).
