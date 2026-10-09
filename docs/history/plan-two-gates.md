# SecureGate: the two gates, demo tokens, and PDF docs

> **Working note, kept as it was written.** The approved plan for the laptop gate, the first merge gate, demo tokens and PDF copies of the docs. Written on 2026-09-30. Built the same day. The pages in [docs/](../README.md) describe SecureGate as it is; [History](README.md) lists every note.

## Context

v0.1 can scan and report. This session makes the result stop leaks in practice:

- **Laptop gate:** a pre-commit hook that scans staged changes before each commit.
- **Merge gate:** a GitHub Actions check named `secret-gate` on every pull request.
- **Demo tokens:** ACME-format fake tokens, so the gate can be shown safely in a public repo.
- **Plain-English docs** for both gates.
- **PDF copies** of every docs page. The `.md` files stay the source.

### Your answers
- PDFs are generated from the `.md` files, committed, and checked for freshness.
- `pre-commit` and `Markdown` are added as dev dependencies.
- The **base branch judges each pull request.**
- actionlint is installed with winget.

### Facts I looked up (not guessed)

| What | Value |
|---|---|
| `actions/checkout`, latest major | v7, released 2026-07-20. v7.0.1 is `3d3c42e5aac5ba805825da76410c181273ba90b1`, the same commit as the floating `v7` tag. |
| `actions/setup-python`, latest major | v7. v7.0.0 is `5fda3b95a4ea91299a34e894583c3862153e4b97`, the same commit as `v7`. |
| v7 breaking changes | Checkout blocks fork checkouts only for `pull_request_target` and `workflow_run`. Setup-python dropped the `pip-install` input. Neither affects us. |
| Gitleaks 8.30.1 (as in CLAUDE.md) | `gitleaks_8.30.1_linux_x64.tar.gz`, sha256 `551f6fc8…2470eb`. That matches GitHub's asset digest and the release's checksums file. |
| Gitleaks checksums file | `gitleaks_8.30.1_checksums.txt`, sha256 `061476c2…52fae` |
| pre-commit 4.6.2 | `system` and `script` now have `unsupported` aliases. The stage name is `pre-commit`. |

### Environment
- Not installed: actionlint (1.7.12 is on winget), gh, pandoc.
- Headless Edge is available and will print the PDFs.
- **This repo has no Git remote.** I won't push. The merge gate first runs once you push and open a pull request.

## 1. Laptop gate

### `.pre-commit-config.yaml`

One local hook, `id: securegate`:
- `language: python`
- `additional_dependencies: [PyYAML, Jinja2]`
- `entry: python tools/precommit_hook.py`
- `pass_filenames: false`, `always_run: true`, `stages: [pre-commit]`

### `tools/precommit_hook.py`

A tiny launcher. It puts this checkout's `src/` on the import path, then runs
`securegate scan . --mode staged --out .securegate/staged-findings.json`.

Why a launcher: pre-commit runs hooks in its own environment. A plain `securegate` or `python`
entry would only work if `.venv` were activated, and on Windows a bare `python` is the system
3.14 without SecureGate. Once `make hooks` has built the hook environment, the hook works offline.

### Output of a blocked commit

After the table, every scan that blocks something now prints one entry per blocked finding:

```
Blocked:
  scripts/deploy.sh:4  acme****x9Qz
    why: provider-keys: A payment, cloud or private key gives direct access ...
    fix: Treat it as leaked. Rotate (replace) the key at the provider now, ...
```

The fix line is the policy's `remediation`, so `policy.yaml` stays the single source. This is
implemented in `report.py` as `blocked_details()` and applies in every mode.

### `make hooks`

Runs `pre-commit install --install-hooks` from `.venv`.

## 2. Merge gate: `.github/workflows/secret-gate.yml`

- **Trigger:** `on: pull_request` with no filters. `permissions: contents: read`.
- **Job:** one job, `secret-gate`, on `ubuntu-latest`, with a 15-minute timeout.
- **Actions:** pinned to the SHAs above, with a `# v7.0.1` / `# v7.0.0` comment next to each.

Steps, each with a plain-English comment:

1. **Checkout.** `fetch-depth: 0`, plus `persist-credentials: false` because the job only reads.
2. **setup-python** with `3.12`.
3. **Install SecureGate from the base branch.**
   - `git worktree add "$RUNNER_TEMP/gate" "$BASE_SHA"`, then `pip install -e .` inside it.
   - `policy.yaml` and `.gitleaks.toml` also come from that worktree.
   - So a pull request can't loosen its own policy or scanner. Its changes take effect after merge.
4. **Install Gitleaks 8.30.1** from the official release:
   - download the archive and the checksums file;
   - check the checksums file against its pinned sha256;
   - check the archive against its line in that file;
   - put the binary in `$RUNNER_TEMP/bin` and add that folder to `$GITHUB_PATH`.
5. **Scan every commit:**
   `securegate scan . --mode range --range "$BASE_SHA..$HEAD_SHA" --policy <base>/policy.yaml --gitleaks-config <base>/.gitleaks.toml --out "$RUNNER_TEMP/findings.json"`.
   - The SHAs come from `github.event.pull_request.base.sha` and `head.sha` through `env:`, which is GitHub's injection-safe pattern. The command is otherwise exactly yours.
   - The exit code decides pass or fail.
6. **Summary**, with `if: always()` and `continue-on-error: true`. It runs
   `securegate summary --report … >> $GITHUB_STEP_SUMMARY`, and falls back to a one-line note if
   SecureGate itself couldn't be set up.

### New command: `securegate summary --report findings.json`

- Prints short Markdown: the result, the range, a table of block and warn findings (where, masked value, why, fix), and the ignored count.
- It reads the report through the dashboard's `load_report()`, which refuses any value that isn't masked.
- It exits 2 if the report is missing or broken, in line with rule 4.
- Code: `src/securegate/summary.py`.

## 3. Demo tokens

- **`securegate demo-token`** prints `acme_live_` plus 32 random letters and digits (Python's `secrets`), a new one every run. The code lives in `src/securegate/demo/token.py`.
- **`docs/demo-merge-gate.md`** gives your seven exact steps, with PowerShell commands.
  - The token goes in `demo_leak.py` at the repo root, not under `docs/` or `tests/`, because those folders only warn.
  - If the laptop gate is installed it will block the commit, so the demo uses `git commit --no-verify`. That shows skipping the laptop gate on purpose.
  - The check stays red after the line is deleted, because the token is still in the PR's history.
  - Close the pull request without merging, then delete the branch.

## 4. Docs, and PDFs

### New pages
- **`docs/merge-gate.md`** covers:
  - the two gates;
  - why only the server gate is the real control: the laptop gate is optional and skippable with `--no-verify`, but the merge gate isn't;
  - the ruleset clicks, exactly as you listed them;
  - that the check only appears in that list after it has run once;
  - one honest caveat: a pull request can edit the workflow file itself, so the doc recommends also requiring a review.
- **`docs/demo-merge-gate.md`**, described above.

### Updated pages
- README map, how-its-built, getting-started (`make hooks`), glossary (pull request, status check, ruleset, workflow), decisions (entries 31 onwards), and CLAUDE.md (new commands and deps, still under 40 lines).

### PDFs
- **`tools/docs_pdf.py` and `make docs-pdf`.** Each `docs/*.md` goes through Markdown to HTML, styled with the dashboard's `tokens.css`, then headless Edge prints it to `docs/pdf/<name>.pdf`.
  - Links between pages point to the matching `.pdf`.
  - The one Mermaid diagram is drawn with Mermaid loaded from a pinned, integrity-checked jsDelivr URL, so internet is needed only while building PDFs.
  - `docs/pdf/manifest.json` records each source's sha256.
- The `.md` files remain what GitHub shows and what the gates scan. Gitleaks skips PDFs.

## Tests (added to `make check`)

| Test | What it proves |
|---|---|
| `test_staged_gate.py` | With the fake runner, and with real Gitleaks on a tmp repo holding a staged demo token, the output has file:line, masked value, why and fix, and never the raw token. A real run of `tools/precommit_hook.py` is blocked (exit 1). |
| `test_demo_token.py` | Output matches `^acme_(live\|test)_[A-Za-z0-9]{32}$`, and two runs differ. Real Gitleaks flags the token as `acme-pay-token` and the policy blocks it. |
| `test_summary.py` | Markdown from the sample report shows masked values only (leak-checked against every planted value). Also covers pass, missing and failed reports. |
| `test_gates.py` | Workflow structure: pull_request only with no filters, contents read, the job id, pinned SHAs, fetch-depth 0, 3.12, base-branch install, the Gitleaks version matching CLAUDE.md, pinned checksum, the range scan, an always-running summary, and a comment above every step. It also checks the pre-commit config and that the hook's deps match pyproject. |
| `test_docs_pdf.py` | Markdown to HTML (links, Mermaid, tables). Every committed PDF matches its `.md`; otherwise "run make docs-pdf". |

## Steps

Each step ends with `make check`, then a commit:

1. `summary` command and "why + fix" output
2. Laptop gate
3. Merge gate plus actionlint
4. `demo-token` and the two docs
5. PDFs
6. Verification

## Verification

- `make check` is green.
- actionlint reports nothing on the workflow.
- In a **temporary clone**, so your own `.git/hooks` stay untouched: `make hooks`, stage a demo token, and `git commit` is blocked with the masked message.
- I open one PDF to check how it looks.
- Not possible here: a real GitHub run. That needs you to push, and the ruleset needs one run first.
