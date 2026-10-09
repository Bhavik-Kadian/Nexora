# Project closure

SecureGate was built by Team Nexora for Microsoft Innovate 2026, Problem Statement 24, between 2026-09-30 and 2026-10-07, and closed out on 2026-10-10 as version 1.0.0. It is finished, not shut down: anyone can clone it, set it up, run it, and protect their own repository with it. It is not actively maintained.

## What was built, and works today

| Part | What it does | Try it |
|---|---|---|
| Find and decide | Gitleaks, and with `--scanners all` also TruffleHog, Semgrep and Bandit, find possible secrets; `policy.yaml` decides block, warn or ignore; every output shows masked values only; the exit code is 0, 1 or 2 | `make demo`, then `make scan-demo` |
| The demo project | DemoPay, a fake payments app with 9 planted secrets and 11 decoys, and an answer sheet for the scorecard | `make demo`, then `make test` |
| The dashboard | The report in the browser, read-only, on this computer only, with downloads and a printable report | `make ui` |
| The menu | Everything above without typing commands | double-click `Start SecureGate.cmd`, or `make menu` |
| The laptop gate | Scans the staged changes before every commit | `make hooks` |
| The merge gate | Scans every commit of every pull request to main with all four scanners, comments, and locks the merge button when the check is red | open a pull request; see [The two gates](merge-gate.md) |
| The GitHub Action | The same merge gate for any repository | `uses: Bhavik-Kadian/Nexora@v1.0.0`; see [Protect any repository](install.md) |
| The demo kit | Five real demo pull requests, clean-up, `doctor` and `ci-report` | menu choice 9; see [Demo: the merge gate](demo-script.md) |
| The AI agents | Triage, fix and incident advice on Azure AI Foundry; advice only, never a whole secret | menu choice A; see [The AI agents](agents.md) |

**The AI agents were verified on Azure** on 2026-10-07, from the laptop, on a `gpt-5-mini` deployment: the connection check passed, and on the demo scan they gave 11 triage notes, 3 suggested fixes and a 10-step incident plan in about 75 seconds. In this repository's merge gate the agents' step is in place, but the repository has no `SECUREGATE_AI_KEY` secret, so the gate's comments say the agents were not asked. [The two gates](merge-gate.md) says how to turn them on.

## Known limitations

The full list, with what to do about each, is in [Limitations](limitations.md). The main ones:

- **The scorecard is honest, not perfect.** With all four scanners, 16 of the 20 planted lines get the expected decision. A password inside a `Dockerfile` is missed, an AWS secret key next to its key id gets a warning instead of a block, and two decoys (an id and a commit hash) get warnings.
- **A pull request can edit the workflow that judges it.** The rules come from main, but GitHub runs the pull request's own copy of the workflow. A required Code Owners review would close this; it needs a second maintainer.
- **ACME Pay tokens cannot be checked for being live**, because the live-checks layer was never built ([Roadmap](roadmap.md)).
- **Pull requests from forks** get no comment, no Security-tab results and no AI advice. Their check still decides.
- **Semgrep needs the internet** for its p/secrets rules, and Semgrep and Bandit are pinned by version, not by checksum.
- **Windows first.** `Start SecureGate.cmd` is for Windows; on macOS and Linux, `make menu` opens the same menu.

## What was switched off at the close-out

- **The demo pull requests.** The 11 that were still open (#6 and #9 to #18) were closed, and their `demo/` branches deleted, here and on the laptop. They held fake ACME Pay tokens only. GitHub keeps closed pull requests, which is harmless.
- **Merged branches** were deleted: the work of each stage is in main.
- **The old Nexora repository** was renamed to Nexora-backup. It only held copies of early branches.

Nothing else was switched off. The merge gate stays on for every pull request. Azure stays up. There was no scheduled workflow, such as a nightly sweep, to switch off.

## How to bring each part back

| Part | How |
|---|---|
| The demo pull requests | `make demo-leak` (or menu 9, then 2), and the other four scenes. They need `gh`, signed in, and a clean working tree. `make demo-cleanup` closes them again. |
| The AI agents in pull request comments | Set the repository secret `SECUREGATE_AI_KEY` and the variables `SECUREGATE_AI_ENDPOINT` and `SECUREGATE_AI_DEPLOYMENT`: "The AI agents" in [The two gates](merge-gate.md). |
| The AI agents, after the Azure resource is deleted | Create a new Azure AI Foundry resource and deployment, then `securegate ai-setup` and `securegate ai-check`: "Set them up" in [The AI agents](agents.md). |
| The ruleset, if it is ever removed | "The one-time setting" in [The two gates](merge-gate.md), by hand or with its one command. |
| The ACME Pay provider and live checks | They were never built, so there is nothing to run or redeploy. The approved plan to build them is kept in [History](history/plan-live-checks-not-built.md). |
| A nightly sweep | There never was one. The [Roadmap](roadmap.md) says how to add one; until then, run `securegate scan . --mode repo --scanners all` by hand. |
| The scanners, on a new computer | `make scanners` (after step 1 of [Getting started](getting-started.md)). |

## Final test and scan results

Measured on 2026-10-10, on the close-out branch, on Windows 11 with Python 3.12.10:

| Check | Result |
|---|---|
| `make check` (ruff, then the tests) | 1029 passed, 1 skipped: a test of POSIX file modes, which Windows does not have |
| Scorecard, the demo project with all four scanners | 16 of 20 planted lines as expected: 1 miss, 1 wrong decision, 2 false alarms |
| Scorecard, Gitleaks alone | 15 of 20 as expected: 2 misses, 1 wrong decision, 2 false alarms |
| `make demo`, then `make scan-demo` | SecureGate exits with code 1, which `make` reports as `Error 1`: 11 findings (6 block, 4 warn, 1 ignore), every value masked |
| `gitleaks git` over every branch's history | 11 findings, all fake ACME Pay tokens, one on each of the 11 demo branches; nothing on main or on any other branch |
| `securegate scan . --mode repo` | exit code 1 while the demo branches existed, for those same fake tokens only |
| Links between the Markdown pages | 0 broken, checked by `tests/test_docs_links.py` |

The checks after publishing, on a fresh clone of the published main and on the release, are added below by the last pull request of the close-out.

## Where everything is

- **The code, the docs and the release:** [github.com/Bhavik-Kadian/Nexora](https://github.com/Bhavik-Kadian/Nexora), release `v1.0.0`. Every page is also a PDF in `docs/pdf/`.
- **What is left for the owner to do:** [CLOSEOUT-CHECKLIST.md](../CLOSEOUT-CHECKLIST.md).
- **What changed, stage by stage:** [CHANGELOG.md](../CHANGELOG.md).
- **The working notes of the build:** [History](history/README.md).
