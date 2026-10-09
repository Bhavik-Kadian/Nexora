# SecureGate close-out plan

Microsoft Innovate 2026, Problem Statement 24. Written on 2026-10-10, before any change, and
approved by Bhavik Kadian before the work started.

"Close" means finished and documented, not shut down: anyone who clones the repository can still
set it up, run it, and protect their own repository with it.

## Decisions

| Question | Decision |
|---|---|
| Home of the project | `Bhavik-Kadian/Nexora`, made by renaming this repository (`Bhavik-Kadian/SecureGate`), which keeps its history, pull requests, gate runs and redirects. The existing Nexora repository (one "Initial commit" and 5 backup branches that copy this repository's) is renamed to `Nexora-backup` first. Nothing is deleted. |
| What "Nexora" is | The team's name. The product stays SecureGate: the package, the `securegate` command and the docs keep that name. |
| License | MIT, Copyright (c) 2026 Team Nexora |
| Azure | The Azure AI Foundry resource (the model the AI agents use) stays up for now. Bhavik deletes it later, with the commands in CLOSEOUT-CHECKLIST.md. The ACME Pay provider and a Key Vault were never built, so nothing else exists in Azure. |
| Archive the repository | No |
| Other repositories | v1.0.0 adds a composite GitHub Action, so `uses: Bhavik-Kadian/Nexora@v1.0.0` protects any repository. It is tried on real pull requests in a new scratch repository first. |
| Team credits | Only Bhavik Kadian, Lead Developer / Backend, until the other names are added. |

## Where things stand

- `main` has PRs #1 to #4. PRs #5 (Layer 2 demo kit), #7 (the AI agents) and #8 (the merge gate
  asks the agents) are green but not merged, so `main` does not have Layer 3 yet.
- 11 demo pull requests are open (#6, #9 to #18), each on a `demo/*` branch with a fake ACME Pay
  token.
- No GitHub issues, no ruleset on `main`, and no description, topics or license on the repository.
- Never built, although the brief mentions them: the ACME Pay provider with its admin token and
  dashboard password, a Key Vault, a nightly sweep, `securegate install`, `action.yml`,
  PROGRESS.md, docs/pitch/, docs/images/ and docs/roadmap.md. This plan adds what a finished
  project needs (the action, a roadmap, screenshots) and says plainly what was never built.
- `make check` on `layer3-workflow`: 981 passed, 1 skipped (a test for POSIX file modes, on
  Windows).
- The saved `gh` login has expired. Bhavik runs `gh auth refresh -h github.com -s workflow`
  before the first GitHub step.

## Ground rules

- Never print or commit a real secret. Rotate, don't just delete.
- Nothing destructive without an explicit yes: no force-push, no history rewrite, no deleting
  repositories or branches with unmerged work, no deleting cloud resources, no archiving.
- A real (non-synthetic) secret anywhere, history included: stop, show where (masked), and push
  nothing until Bhavik confirms it is rotated.
- No behaviour changes beyond the list below.
- The work happens on `chore/closeout`, in small commits, with `make check` green before each
  one, and reaches `main` through a pull request that our own gate checks.

## Approving this plan says yes to these GitHub actions, and only these

1. Merge PRs #5, #7 and #8, in that order, as merge commits.
2. Rename `Bhavik-Kadian/Nexora` to `Bhavik-Kadian/Nexora-backup`, then `Bhavik-Kadian/SecureGate`
   to `Bhavik-Kadian/Nexora`.
3. Set the repository's description and topics, turn on private vulnerability reporting, and
   create the "Protect main" ruleset from docs/merge-gate.md: pull request required, `secret-gate`
   check required, no deleting or force-pushing `main`, and an empty bypass list.
4. Push `chore/closeout` (and one last docs branch), open their pull requests, and merge them
   once the gate is green.
5. Create the public scratch repository `Bhavik-Kadian/securegate-action-demo` and open two pull
   requests there to try the action: a harmless one (green), and one with a fake token from
   `securegate demo-token` (red, then closed).
6. Tag `v1.0.0` and create the GitHub release.
7. Close the 11 demo pull requests and delete their 11 `demo/*` branches, on GitHub and here
   (`securegate demo-cleanup`). They were never meant to be merged and hold fake tokens only.
8. Delete the merged branches `layer2-engine`, `layer2-workflow`, `layer2-presenting`,
   `menu-four-scanners`, `layer2-demo-kit`, `layer3-agents` and `layer3-workflow`, and
   `chore/closeout` once it is merged.

Nothing in Azure is touched. Nexora-backup and its branches stay as they are.

## Behaviour changes to approve

1. The merge gate runs on `ubuntu-24.04` instead of `ubuntu-latest`, which becomes Ubuntu 26 from
   2026-10-19. The finished gate keeps the image it was tested on.
2. The version becomes 1.0.0: `securegate version`, the menu, reports and SARIF show it.
3. SARIF's `informationUri` points to `https://github.com/Bhavik-Kadian/Nexora`.
4. Exact dependency pins: pyproject.toml pins the direct dependencies and the build backend, a
   new constraints.txt pins everything they pull in (`make setup` and the action use it), and the
   pre-commit hook pins its two packages. These are the versions tested today.
5. New, and additive: `action.yml`, the composite action. This repository's own gate stays as it
   is.

Everything else is cleanup and documentation. It does not change what SecureGate does.

## Phase 1: safety sweep

Run read-only on 2026-10-10, and again before the first push:

- `gitleaks git --log-opts=--all` over every branch: 11 findings, all `acme-pay-token` (the
  demos' invented provider), one per `demo/*` branch, in `demo-app/payments.py` (8 leak demos)
  and `demo-app/tests/test_payments.py` (3 decoy demos). Nothing on `main` or any work branch.
- `securegate scan . --mode repo`: exit 1, for the same 11 fake tokens only (8 block, 3 warn).
  Repo mode reads every branch, so it exits 0 once Phase 5 deletes the demo branches.
- No .env, key, report, findings, demo repository, database or log file was ever committed, on
  any branch. `sample_findings.json` is tracked on purpose: the designers' sample report, with
  masked values only.
- .gitignore already covers `.env*`, `*.pem`, `*.key`, `.securegate/` (with `local.key`),
  `findings*.json`, `reports/`, `securegate-demo/` and `reference/`. It gains `*.sqlite`,
  `*.sqlite3`, `*.log` and `logs/`.
- The one real secret on this laptop, the Azure AI key, is in `.securegate/ai.json`, which Git
  ignores and which was never committed.
- Once `gh` is logged in: `gh secret list` and `gh variable list`, names only, for the checklist.

## Phase 2: code cleanup

`chore/closeout` starts from `layer3-workflow`, which already holds #5, #7 and #8. Once those
three are merged, the close-out pull request shows only its own commits.

1. First commit: this plan, as docs/history/closeout-plan.md.
2. Dead code and unused files: list every function, class, template and file that nothing
   refers to, and remove the dead ones. A removal that would change behaviour is listed and asked
   about first. Today there are no TODO or FIXME markers, debug prints or commented-out blocks;
   that is checked again at the end.
3. Type hints on the few public functions still without them. `ruff check` and `ruff format`
   stay clean.
4. The pins and the runner (behaviour changes 4 and 1).
5. The composite action (behaviour change 5), `action.yml` at the root. It installs SecureGate
   from the tag it is used at, checks Gitleaks and TruffleHog against their published checksums,
   installs the pinned Semgrep and Bandit, and scans every commit of the pull request. It writes
   the job summary, one pull request comment, SARIF and findings.json, then passes or fails with
   SecureGate's exit code (0, 1 or 2; an error fails closed). The policy comes from the caller's
   base branch (their policy.yaml, or SecureGate's own when the base has none), so a pull request
   cannot loosen the rules that judge it. Tests check that its scanner versions, checksums and
   action pins match the workflow's, that no GitHub data is pasted into a script, and that it
   fails closed.
6. The product is already called SecureGate everywhere (checked). References to
   `Bhavik-Kadian/SecureGate` become `Bhavik-Kadian/Nexora`.
7. Version 1.0.0.

## Phase 3: docs for a finished project

- **README.md**, the front page:
  - a one-line pitch, and the problem in three sentences;
  - the three layers: find and decide on the laptop, the four-scanner merge gate, the AI agents;
  - screenshots in docs/images/, taken from the real dashboard and a real pull request comment
    (masked values only);
  - a five-command quick start, and "Protect any repo" linking docs/install.md;
  - a Mermaid architecture diagram and the tech stack;
  - the status line "Completed: built for Microsoft Innovate 2026 (Problem Statement 24). Not
    actively maintained.";
  - the credits and the license.
- **docs/README.md**: the index, linking every page, docs/history/ included.
- **New pages**:
  - docs/install.md: protect any repository (the action, the ruleset, the laptop gate);
  - docs/roadmap.md: what was planned and not built, with links;
  - docs/project-closure.md: what was built and works today, known limitations, what was
    switched off, how to bring each part back, and the final test and scan results.
- **Every page checked against the code**, with built and planned clearly apart. Three agents
  exist (triage, fix, incident). Live checks for ACME Pay (policy rule 2) were planned, not
  built. There is no nightly sweep.
- **docs/presenting-to-judges.md**, the long judging-day script that demo-day.md replaced, moves
  to docs/history/. Anything in it that is still useful moves to the right page first.
- **Working notes into docs/history/**: PLAN.md, plus the approved plan of each stage (the two
  gates, the launcher and menu, Layer 2, Layer 3, and the live-checks plan that was never
  built). Each one passed `gitleaks dir`. CLAUDE.md stays at the root and is updated.
- **New at the root**:
  - CHANGELOG.md;
  - SECURITY.md: every key here is synthetic, report problems privately through GitHub, and the
    project is not actively maintained;
  - LICENSE;
  - CLOSEOUT-CHECKLIST.md.
- **docs/pitch/** does not exist. If the deck should go in, its files go there and pass
  `gitleaks dir` before they are added.
- **A test** that fails on a broken link in any Markdown file, and `make docs-pdf` for every
  changed page.

## Phase 4: publish to Bhavik-Kadian/Nexora

1. Rename the repositories (yes 2), and point the local remotes at the new names: `origin` to
   Nexora, and `nexora` renamed to `backup`, pointing at Nexora-backup.
2. Set the description and the topics (secret-scanning, devsecops, github-actions, gitleaks,
   trufflehog, semgrep, python, hackathon), turn on private vulnerability reporting, and create
   the ruleset.
3. Merge #5, #7 and #8. Push `chore/closeout` and open its pull request. Try the action from that
   commit in the scratch repository: one green pull request and one red. The gate on the
   close-out pull request goes green; merge it.
4. Tag `v1.0.0` and create the release. Its notes say what is included, how to use it
   (`uses: Bhavik-Kadian/Nexora@v1.0.0`), and the known limitations. The scratch repository then
   switches to `@v1.0.0` and runs once more.

## Phase 5: close

1. `securegate demo-cleanup` closes the 11 demo pull requests and deletes their branches (yes
   7). There is no other demo target repository: demo pull requests were always opened here.
2. Delete the merged branches (yes 8).
3. Issues: there are none to label or close, so docs/roadmap.md holds the ideas instead.
4. Nightly sweep: none exists, so there is nothing to switch off. The only workflow is the pull
   request gate, and it stays on. The roadmap shows how to add a scheduled sweep.
5. CLOSEOUT-CHECKLIST.md, the steps only Bhavik can do:
   - revoke or rotate the tokens we used: `gh`'s login, any personal access tokens, Git
     Credential Manager's GitHub login, and the Azure AI key (the ACME admin token and dashboard
     password never existed);
   - Azure is kept, with the exact commands to delete and purge it later;
   - the repository's secrets and variables, by name, and when to remove them;
   - collaborator access;
   - archiving, in case of a change of mind;
   - what to do with Nexora-backup and the scratch repository.

## Final verification, shown to Bhavik

- A fresh clone of `Bhavik-Kadian/Nexora` in a temporary folder passes
  `make setup && make check`.
- `make demo && make scan-demo` prints a masked table and exits 1.
- `securegate scan . --mode repo` on the published `main` exits 0.
- The latest `secret-gate` run is green (the gate runs on pull requests to `main`), release
  `v1.0.0` exists, and docs/ has no broken links.
- One last small pull request records these results in docs/project-closure.md, so `main` ends
  one docs commit ahead of the tag.
- Then a ten-line summary of everything that changed.
