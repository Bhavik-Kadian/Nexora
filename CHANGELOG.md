# Changelog

What changed in SecureGate, newest first. Dates are when the work reached the code. Version 1.0.0 is the only tagged release: before it, the version stayed 0.1.0 while the project grew in stages, each one listed here.

## 1.0.0: the close-out (2026-10-10)

The finished project, after Microsoft Innovate 2026 (Problem Statement 24). It is not actively maintained.

**Added**

- `action.yml`: the merge gate as a GitHub Action, so any repository can use it with `uses: Bhavik-Kadian/Nexora@v1.0.0`. SecureGate comes from the action's tag and the policy from the caller's base branch; it fails closed. Tests keep it in step with the workflow. See [Protect any repository](docs/install.md).
- `constraints.txt`, with the exact version of every package installed; `make setup` uses it.
- The MIT license, [SECURITY.md](SECURITY.md), this changelog and [CLOSEOUT-CHECKLIST.md](CLOSEOUT-CHECKLIST.md).
- Docs: [Project closure](docs/project-closure.md), [Roadmap](docs/roadmap.md) and [History](docs/history/README.md), the working notes of the build. Getting started now lists every command and what to do when something goes wrong.
- A test that fails on a broken link in any Markdown file.

**Changed**

- The repository is `Bhavik-Kadian/Nexora`, renamed from `Bhavik-Kadian/SecureGate`; GitHub redirects the old address. SARIF's `informationUri` points to it.
- `pyproject.toml` pins the direct dependencies and the build backend at the versions tested.
- The merge gate runs on `ubuntu-24.04` instead of `ubuntu-latest`.
- Getting started installs Gitleaks 8.30.1 exactly, the version SecureGate is tested with.
- The judging-day script and the build plan moved to `docs/history/`.

**Removed**

- An unused constant in `pipeline.py`.

## Layer 3: the AI agents (2026-10-07, pull requests #7 and #8)

- Three AI agents on Azure AI Foundry, `securegate agents`: **triage** (likely real or a false alarm, and why), **fix** (a line that reads the key from the environment instead) and **incident** (the response plan for blocked keys). They advise only, and never see a whole secret: SecureGate takes every value out first.
- The advice is kept in the report, checked again whenever it is read, and shown in the pull request comment, the job summary, the dashboard (an AI advice page) and the menu (choice A).
- `securegate ai-setup` and `ai-check`, also in `make doctor`.
- `securegate agent-fix --pr N`: a fix pull request into a pull request's branch, with the edit made by SecureGate itself.
- The merge gate asks the agents after it has decided, in a step that can never fail the check.
- Demo day, the whole demo on one page from the menu, and a front-page README.

## Layer 2: the merge gate (2026-10-04 to 2026-10-06, pull requests #1 to #5)

- Four scanners, one verdict: TruffleHog, Semgrep and Bandit join Gitleaks (`--scanners all`). Findings of the same secret and line are merged, and name every scanner that found them.
- Numbered policy rules (1, 3, 7, 8, 9, 10, 13 and 14), and live checks: TruffleHog asks the providers it knows whether a key still works, and rule 1 blocks a live key.
- SecureGate's own Semgrep rules for risky handling of secrets.
- The pull request comment, the job summary and SARIF, all made from the checked report.
- The four-scanner merge gate on every pull request to main: SecureGate and its rules from the base branch, pinned and checksum-checked scanners, one comment, and the exit code decides last.
- The demo kit: five demo pull requests (`securegate demo-pr`), `demo-cleanup`, `doctor` and `ci-report`, and the merge gate in the menu (choice 9).
- `make scanners`, which installs TruffleHog, Semgrep and Bandit at the pinned versions.

## The launcher, the menu and the dashboard's second look (2026-10-01 to 2026-10-04)

- `Start SecureGate.cmd`: double-click to start SecureGate.
- `securegate menu`: SecureGate's own menu with terminal art, which the launcher opens.
- The dashboard: a dark theme, CSV, JSON and Markdown downloads, a printable report, and it never shares a busy port.

## 0.1.0: the first build (2026-09-30)

- Gitleaks finds, `policy.yaml` decides (block, warn or ignore), and every output shows masked values and fingerprints only. Exit codes 0, 1 and 2; errors fail closed.
- The demo project generator (DemoPay, seed 42), its answer sheet and the scorecard.
- The read-only dashboard, on 127.0.0.1 only, with no JavaScript.
- The two gates: the laptop gate (pre-commit) and the first merge gate (GitHub Actions, with Gitleaks).
- `securegate summary` and `securegate demo-token`, and PDF copies of the docs.
