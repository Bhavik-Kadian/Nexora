# SecureGate Layer 2: the merge gate (four scanners, one verdict)

> **Working note, kept as it was written.** The approved plan for Layer 2: four scanners, one verdict, the pull request comment, SARIF and the demo kit. Written on 2026-10-04. Built from 2026-10-04 to 2026-10-06 (pull requests #1 to #5). The pages in [docs/](../README.md) describe SecureGate as it is; [History](README.md) lists every note.

## Context

Layer 1 already exists:
- an engine where the policy decides and everything is masked
- the Gitleaks adapter
- policy.yaml
- the pre-commit hook
- a Gitleaks-only `secret-gate` workflow
- the dashboard

Layer 2 makes every pull request to main be scanned on GitHub by Gitleaks, TruffleHog, Semgrep and Bandit. Their findings merge into one verdict decided by policy.yaml. The PR gets a comment, a SARIF upload and a job summary, and a red check locks the merge button. A demo kit (`demo-pr`, `doctor`) makes it safe to show live to judges.

I extend the engine; nothing is rewritten. With the default `--scanners gitleaks`, today's behaviour stays exactly the same (hook, menu, `make scan-demo`, existing tests).

**Your answers:**
- Create the GitHub repo with gh (I ask before running it).
- Install Semgrep + Bandit in .venv, TruffleHog 3.97.9, and gh via winget.
- Commit the dashboard work first.
- Keep the base-branch install. Layer 2 therefore ships in **two PRs**:
  - **PR A:** the engine, judged by today's Gitleaks gate.
  - **PR B:** the workflow. It is judged by Layer 2 code from main, so the PR that adds the Layer 2 gate passes its own four-scanner gate.

**Versions looked up today (2026-10-04):**

| Tool or action | Version |
|---|---|
| TruffleHog | 3.97.9 (linux/windows amd64 archives plus `trufflehog_3.97.9_checksums.txt`) |
| Semgrep | 1.179.0 (has a win_amd64 wheel) |
| Bandit | 1.9.4 |
| gh | 2.102.0 (winget `GitHub.cli`) |
| actions/checkout | v7.0.1 (already pinned) |
| actions/setup-python | v7.0.0 (already pinned) |
| actions/upload-artifact | v7.0.1 @ `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| github/codeql-action/upload-sarif | v4.38.2 @ `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` |

I re-check all of these when the workflow is written.

## M0: Before M1 (I ask before each outward step)

1. Run `make check`, then commit the 33 dashboard files as one commit.
2. `winget install GitHub.cli`. You run `! gh auth login`.
3. `gh repo create securegate --public --source . --remote origin --push`. I'll confirm the name with you first. Today's Gitleaks workflow then guards main.

## Design

### Scanner adapters (`src/securegate/scanners/`), same shape as `gitleaks.py`

Every adapter follows the same pattern:
- the runner is injected
- `probe()` checks the flags against `--help` (it fails if a needed flag is missing)
- `build_command()` and `parse_*()` are pure functions
- `scan()` returns `Candidate`s

`Candidate` moves to `scanners/candidate.py`. `gitleaks.py` re-exports it and keeps its API. Candidate gains:
- `detector` (default `"gitleaks"`)
- `validity` (default `"not_checked"`)

The raw value is masked and fingerprinted in `pipeline.py`, exactly as today.

| Scanner | Command (only flags confirmed by the installed `--help`) | Read in memory only | Never stored |
|---|---|---|---|
| Gitleaks (required) | unchanged | unchanged | unchanged |
| TruffleHog (required) | `trufflehog git file://<repo> --since-commit <base> --branch <head> --json --no-update --no-ignore-tag --fail-on-scan-errors --results=verified,unknown,unverified [--no-verification] [--config .trufflehog.yaml]`. No `--fail`. In repo mode, no range. | `DetectorName`, `Verified`, whether `VerificationError` is set, `Raw` (the value), `SourceMetadata.Data.Git` file/line/commit/timestamp, author name from email | `Raw`, `RawV2`, `Redacted`, `ExtraData`, `StructuredData`, the error text |
| Semgrep (optional) | `python -m semgrep scan --config p/secrets --config rules/securegate-risky.yml --json --metrics off --disable-version-check --disable-nosem --no-git-ignore <private copy>` | `check_id`, path, start line, start/end offsets (to cut the value out of our own copy) | `extra.lines`, `extra.message`, metadata, fix, dataflow trace |
| Bandit (optional) | `python -m bandit -f json -q -t B105,B106,B107 --ignore-nosec <changed .py files>` | `test_id`, filename, line, `issue_text` (only to pull out the quoted password) | `code`, `issue_text`. The message is built from the test id. |

- **TruffleHog parsing.** JSON lines are parsed defensively. Non-JSON lines (logs) are skipped and never echoed. A malformed finding line gives exit 2, naming only its line number.
- **Validity:**
  - `Verified` gives `verified`.
  - A verification error gives `unknown`.
  - Otherwise `unverified`. Reports call this "not confirmed", never "safe".
  - `--no-verification`, and the other scanners, give `not_checked`.
- **Semgrep and Bandit targets.** They scan a **private temp copy** of the files changed in the PR (`git diff --name-only --diff-filter=d base...head`) as they are at head (`git show head:path`).
  - In repo mode they scan all tracked files at HEAD.
  - Config-like files (`.semgrepignore`, `.gitignore`, `.bandit`) are not copied, and SecureGate writes its own empty `.semgrepignore`. So a PR can't hide files from them.
  - This lives in `scanners/changes.py`, with an injected git runner.
- **When p/secrets can't load.** If the first Semgrep run fails, Semgrep re-runs with local rules only. The report then says "Semgrep could not load p/secrets (no internet?), so it ran SecureGate's own rules only."
- **Which scanners run.** `--scanners gitleaks` is the default; `--scanners all` runs all four.
  - TruffleHog, Semgrep and Bandit run in **repo and range modes**.
  - In dir and staged modes they are reported as "skipped", with validity `not_checked`.
- **Required vs optional.**
  - Gitleaks or TruffleHog missing or crashing raises `ScannerError`, which gives exit 2 (the error envelope, as today).
  - Semgrep or Bandit failing is recorded as `did not run: <safe reason>` (exit code, timeout or "not installed", never stderr), and the scan continues.

### Merge (`src/securegate/merge.py`, pure)

1. **Each scanner's finding is decided on its own.** The policy runs first match wins, as today; `decide()` gains `validity=`.
2. **One finding per file and line.**
   - Gitleaks and TruffleHog findings of the same key (same fingerprint) in the same file and commit merge, even if TruffleHog's line drifts.
   - Semgrep and Bandit findings join the secret finding on their file:line, by adding themselves to its `detectors` instead of becoming a separate finding.
   - With no secret finding on that line, Semgrep and Bandit findings on the same line merge with each other.
   - Two *different* secrets on one line, found by the same scanner, stay separate.
3. **What a merged finding keeps:**
   - **Decision:** the strongest (block > warn > ignore), with that rule's label, reason and fix.
   - **Severity:** the highest.
   - **Validity:** the strongest (verified > unknown > unverified > not_checked).
   - **Detectors:** in the order gitleaks, trufflehog, semgrep, bandit.
   - **Masked value, rule, commit and author:** from the primary finding (a secret scanner first).

### Policy (`policy.yaml` and `policy.py`)

- Each rule gets a new key, `number:`. It is optional; if any rule has one, all must. Numbers are unique and ascending, and gaps are allowed.
- There is a new condition, `validity: [...]`.
- `Verdict.label` gives "rule 8: provider-keys". The `reason` stays "name: text", so the dashboard and existing parsing keep working.
- `rule_ids` now also take `trufflehog-<detector>`, Semgrep rule ids and `bandit-B105` and friends.

| # | name | when | decision, severity |
|---|---|---|---|
| 1 | verified-live | `validity: [verified]` | block, critical |
| 3 | placeholders | existing | ignore, info |
| 7 | tests-fixtures-docs | `**/tests/**`, `**/fixtures/**`, `**/docs/**`, `**/*.example`, `**/*.md` | warn, medium |
| 8 | provider-keys (name and reason text kept) | value starts with `acme_live_`, `sk_live_`/`rk_live_`, `AKIA`, `ghp_`/`github_pat_`, or is a private-key block (the regex is written as `-{5}BEGIN...`). Plus Addition 4. | block, high |
| 9 | test-mode-keys | `^acme_test_`, `^[sr]k_test_` | warn, medium |
| 10 | hardcoded-passwords | `rule_ids`: bandit-B105/B106/B107, generic-api-key, and the generic-secret ids from p/secrets | warn, medium |
| 13 | risky-handling | `rule_ids`: our 3 Semgrep rules | warn, low |
| 14 | everything-else | (none) | warn, medium |

### Custom rules (`rules/securegate-risky.yml`, Python)

| Rule id | What it catches |
|---|---|
| `securegate-secret-logged` | a variable named like key/token/secret/password passed to `print` or a logging call. f-strings and %-format count; string literals are excluded. |
| `securegate-secret-in-url` | a secret-named variable put into a URL query string |
| `securegate-getenv-default` | `os.getenv` / `os.environ.get` with a hardcoded string default |

### Finding and findings.json (additive; `schema_version` stays 1)

- **Finding** gains `detectors`, `validity` and `matched_rule` ("rule 8: provider-keys"). They default to what Layer 1 produces.
- **The envelope** gains `scanners: [{name, version, required, status: ran|did_not_run|skipped, note}]`. The existing `scanner` (Gitleaks) is kept.
- **The dashboard** loader reads the new fields when present. The finding page shows "Found by", "Live check" and "Policy rule". Layer 1 reports still load.
- **`confidence.py`:** `bandit-*`, `securegate-*` and Semgrep generic ids count as generic matches.

### Outputs (`securegate scan --sarif F --summary F --comment F`)

All three are rendered from findings.json **re-read through `ui/report_view.load_report()`**, which refuses any unmasked value. That is the same rule the dashboard's downloads follow.

**PR comment** (`outputs/markdown.py` with the template `outputs/templates/report.md.j2`):
- a hidden `<!-- securegate:pr-comment -->` marker
- a one-line verdict: **BLOCKED**, **PASSED WITH WARNINGS**, **PASSED**, or **ERROR** for exit 2
- a table: Decision | Rule | Where | Masked value | Found by | Live check
- a red "Semgrep did not run" line, using GitHub's LaTeX `\color{red}` with a 🔴 prefix
- for every block, a checklist for its provider (ACME, Stripe, AWS, GitHub, or generic, in `outputs/rotation.py`, which reuses `ui/fixes.REVOKE_AT`):
  - revoke the key at the provider
  - create a new one
  - store it in a secret manager
  - replace the line with `os.environ["ACME_PAY_API_KEY"]` (the variable name depends on the provider)
  - confirm the old key no longer works
  - the sentence "Deleting the line is not enough: the key stays in Git history."
- "Why these were not blocked": every warning with its rule and reason
- a collapsed list of the ignored findings and why they were ignored
- at most 50 rows, to stay under GitHub's comment limit

**Job summary:** the same body without the marker. `summary.py` and `securegate summary` now use it.

**SARIF 2.1.0** (`outputs/sarif.py`):
- built from our findings, never from the scanners' raw output
- one SARIF rule per policy rule, with `security-severity`
- block and warn results only; block becomes `error`, warn becomes `warning`
- the message holds the masked value, the rule, the detectors and the live check
- no partialFingerprints (upload-sarif computes them)
- **not written on exit 2**, and any stale file is deleted, so the Security tab never receives an empty "all clear"

### Workflow (`.github/workflows/secret-gate.yml`)

- **Trigger:** `pull_request: branches: [main]`, with no path filters.
- **Concurrency:** grouped by PR number, `cancel-in-progress: true`.
- **Permissions:** contents read, pull-requests write, security-events write.
- **Job:** one job named `secret-gate` on ubuntu-latest, `timeout-minutes: 10`.
- **Pins:** one top-level `env:` block holds `GITLEAKS_VERSION`, `GITLEAKS_CHECKSUMS_SHA256`, `TRUFFLEHOG_VERSION`, `TRUFFLEHOG_CHECKSUMS_SHA256`, `SEMGREP_VERSION` and `BANDIT_VERSION`. The same pins go in CLAUDE.md, and a test checks they match.

Steps, each with a plain-English comment:
1. checkout (`fetch-depth: 0`, `persist-credentials: false`)
2. setup-python 3.12 with `cache: pip`
3. install SecureGate **from the base branch** (kept). Its policy.yaml, .gitleaks.toml, rules/ and .trufflehog.yaml are used too.
4. install Gitleaks, verified against the pinned checksums file (kept)
5. install TruffleHog the same way (pinned SHA-256 of its checksums file, then the archive's line), with no `curl | sh`
6. `pip install semgrep==… bandit==…`
7. scan `"$BASE_SHA..$HEAD_SHA"` with `--scanners all` and every output. The exit code goes to `$GITHUB_OUTPUT` with `set +e`.
8. Always:
   - append the summary
   - upload the SARIF (`category: secret-gate`; skipped on exit 2 and for forks)
   - upload findings.json as artifact `findings`
9. post or update the comment by finding the marker with `gh api`, using `GH_TOKEN: github.token`. Skipped for forks. Comment and SARIF failures never change the result.
10. last step: `exit "${SCAN_EXIT:-2}"`

Untrusted values only ever reach the scripts through `env:`, never as `${{ }}` inside a script.

### Demo kit

- **`securegate demo-pr <clean|leak|deleted-later|decoys|risky>`** (`demo/pull_requests.py`, templates in `demo/pr_templates/`):
  - It refuses unless the working tree is clean, gh is logged in and origin exists.
  - It works in a **temporary git worktree** made from `origin/main` on `demo/<scenario>-<UTC time>`. Your checkout never changes.
  - It commits with `--no-verify`, so the laptop gate doesn't stop the demo leak.
  - It pushes only that refspec and opens the PR with `gh pr create --base main`. The PR body explains the expected result.
  - Tokens come from `demo/token.py` at runtime: `acme_live_`, and a new `acme_test_` helper. The password and UUID are random too.
  - It never pushes, commits to or deletes `main`; branch names are checked against `^demo/`.
- **The five scenarios:**

  | Scenario | What the PR contains | Expected result |
  |---|---|---|
  | clean | a harmless change | green |
  | leak | an `acme_live_` token in `demo-app/payments.py` | red: rule 8 |
  | deleted-later | the token added in one commit, replaced by `os.environ[...]` in the next | still red |
  | decoys | `YOUR_API_KEY_HERE`, `changeme`, a UUID and an `acme_test_` token in `demo-app/tests/` | green: rule 3 ignores, rule 7 warns, each explained |
  | risky | a token from the environment that is then logged, and a hardcoded password | green: warnings from rule 13 (Semgrep) and rule 10 (Bandit) |

- **`securegate demo-cleanup`:** closes every open PR whose head is `demo/*` (`--delete-branch`), deletes the remaining remote and local `demo/*` branches, and nothing else.
- **`securegate doctor`:** PASS/FAIL/SKIP lines; exit 0 when nothing failed, 1 when something did. It checks:
  - local Gitleaks, TruffleHog, Semgrep and Bandit versions against the workflow's pins
  - policy.yaml loads
  - `gh auth status`
  - the workflow exists locally and on GitHub's main, with job `secret-gate`
  - `gh api repos/{o}/{r}/rules/branches/main` has a required status check `secret-gate` (SKIP if no permission)
- **`securegate ci-report`** downloads artifact `findings` from the latest secret-gate run with gh and opens the dashboard on it.
- **Make targets:** `demo-clean`, `demo-leak`, `demo-deleted`, `demo-decoys`, `demo-risky`, `demo-cleanup`, `doctor`, `ci-report`, `scanners`.

### Local tools

- `make scanners` runs `tools/install_scanners.py`, which reads the pins from the workflow's env block (one source of truth):
  - `pip install` the pinned Semgrep and Bandit into .venv
  - download the TruffleHog release for this OS, check it against the pinned checksums file and that file's archive line, and extract only the binary into .venv\Scripts
- `programs.find_program` also looks in the running Python's Scripts folder. That is never the current folder or a scanned repo.

## Milestones (after each: `make check`, show you the output, wait; then one commit on the branch)

1. **TruffleHog adapter, merge logic, policy rules**
   - install_scanners plus `make scanners`
   - record the real `trufflehog --help` and `trufflehog git --help` flags in PLAN.md (I add a Layer 2 section)
   - `candidate.py`, `trufflehog.py`, `.trufflehog.yaml`
   - `merge.py`, the new finding fields, the policy number/validity support, the new policy.yaml
   - the pipeline runs several scanners (required/optional), the scanners list in the envelope
   - CLI `--scanners`, `--no-verification`, `--trufflehog-config`
   - tests:
     - `fake_trufflehog.py` (JSON lines built at runtime)
     - an adapter test (flags, the validity mapping, defensive parsing, raw fields never kept)
     - a real-TruffleHog test (skipped without the binary; always `--no-verification`; a range whose base is not an ancestor)
     - `test_merge.py`
     - tests for every new rule
     - TruffleHog crashing gives exit 2
2. **Semgrep and Bandit adapters, custom rules**
   - `changes.py`, `semgrep.py`, `bandit.py`, `rules/securegate-risky.yml`, `--semgrep-rules`, the p/secrets fallback
   - tests:
     - fakes that plant raw values in `extra.lines`, the message, `code` and `issue_text`, and prove none of them survive
     - an optional failure lets the scan continue and is reported as did_not_run
     - the custom rules checked by real Semgrep on samples built at runtime (skipped without Semgrep)
     - real Bandit
     - the integration test: four scanners on the demo repo, printing hits, false alarms and misses **per scanner** (`scorecard.score_by_detector`). It asserts that `--no-verification` was used.
3. **Outputs (comment, SARIF, summary)**
   - `outputs/` (markdown, rotation, sarif, template); `report_view` and the finding page read the new fields; the CLI output flags
   - tests:
     - comment: the verdicts, every block has its checklist and the sentence, the marker, the red did-not-run line, truncation
     - SARIF shape and levels
     - the summary
     - **leak test:** all four fakes on the generated demo repo; no planted value in findings.json, SARIF, summary, comment, stdout or stderr
   - Then, asking you first, I push `layer2-engine` and open **PR A**. It must pass today's gate before you merge it.
4. **Workflow**
   - the new secret-gate.yml, the pins in CLAUDE.md, the test_gates workflow half rewritten, an actionlint test (skipped without actionlint)
   - after PR A is merged: **PR B** must turn green under its own four-scanner gate
   - then the main ruleset requires `secret-gate`. I can do this via `gh api` if you OK it, or you follow merge-gate.md.
5. **Demo kit and doctor**
   - demo-pr, demo-cleanup, doctor, ci-report, the Makefile targets
   - tests use fake gh runners and a real temporary repo with a bare local "origin": refuses a dirty tree, never touches main, the exact refspec, the content of each scenario (checked with booleans and masks only)
   - live: `make demo-leak` (red, locked, a clear comment), `make demo-decoys` (green, explained), the other three, `securegate doctor` all green, `make demo-cleanup`
6. **Docs**
   - `merge-gate.md`: the four scanners, the merge rules, the decision order, the outputs, a Mermaid diagram
   - `demo-script.md`: five scenes, each with its command, what the judges see, one line to say and how long it takes, plus a backup plan (screenshots and a recorded video)
   - `limitations.md`: PRs can edit the workflow (CODEOWNERS plus a code-owner review); Semgrep and Bandit see only the current files; TruffleHog verifies only the services it supports
   - `.github/CODEOWNERS`
   - updates to README, how-its-built, glossary, decisions, testing, getting-started and presenting-to-judges
   - `make docs-pdf`
   - **PR C** (M5 and M6), judged by Layer 2

## Existing tests that must change (the spec changes the behaviour they pin)

| Test file | What changes |
|---|---|
| `test_policy.py` | About 8 tests of the *shipped* policy's contents: rule names; the tests-fixtures-docs severity goes from low to medium; `documentation.md` now warns (`*.md`); provider and GitHub keys are matched by value format, and critical becomes high; generic-api-key now hits rule 10. The engine tests stay unchanged. |
| `test_pipeline.py` | One assertion: critical becomes high. |
| `test_finding.py` | `FIELD_ORDER` gains detectors, validity and matched_rule. |
| `test_summary.py` | The table header; "PASS" becomes "PASSED"; the cell-escaping test moves to the new sections. |
| `test_gates.py` | The workflow half is rewritten in M4. The hook half stays unchanged. |

Anything else that turns out to pin Layer 1 behaviour gets listed at that milestone's checkpoint. I won't change any of it silently.

## Additions beyond the spec (veto any)

1. **Nothing can silence a finding outside the policy.** TruffleHog `--no-ignore-tag`, Semgrep `--disable-nosem`, Bandit `--ignore-nosec`, and the private copy without the repo's ignore files.
2. **TruffleHog stays fixed and fails closed.** `--no-update`, `--fail-on-scan-errors` (a partial scan fails closed), and an explicit `--results`.
3. **`.trufflehog.yaml`** with an ACME custom regex detector and no verify endpoint (so no network). The demo then shows "Found by: Gitleaks, TruffleHog", and next session can add the ACME live check here.
4. **Rule 8 keeps blocking what Layer 1 blocked.** It also matches `gho_`/`ghu_`/`ghs_`/`ghr_`, the AWS key ids `ASIA`/`ABIA`/`ACCA`/`A3T…` and Bedrock keys, so none of them becomes a mere warning.
5. **Merging tolerates drifting line numbers.** The same key in the same file and commit merges even if the line numbers differ.
6. **Extra options.** `--scanners`, `--no-verification`, `--semgrep-rules`, `--trufflehog-config`. `make scanners` reads its pins from the workflow, and `find_program` also looks in the venv's Scripts folder.
7. **`securegate ci-report`** behind `make ci-report`.
8. **Outputs are re-checked for masking**, and no SARIF is written on exit 2.
9. **The comment lists ignored findings**, collapsed, so the decoys scene explains the placeholders too. Comments are cut off at 50 rows.
10. **demo-pr uses a temporary worktree and `--no-verify`.**
11. **The dashboard finding page shows the new fields.**
12. **demo-script.md replaces docs/demo-merge-gate.md** (the manual Layer 1 demo), and its links are updated.
13. **CODEOWNERS also covers** `.gitleaks.toml`, `rules/` and `.trufflehog.yaml`.
14. **A workflow test** checks that no `${{ github.event… }}` appears inside a `run:` script.

## Consequences worth knowing

- **Rule order is as specified, with rule 7 before rule 8.** A live key in tests/, docs/ or any `.md` file only *warns*, unless TruffleHog confirms it live (rule 1).
- **Rule 8 is "high" now; only verified keys are "critical".**
- **CODEOWNERS can't be enforced yet.** On a one-person repo, ticking "Require review from Code Owners" would block every PR that touches .github/ or policy.yaml, so leave it off until there's a second maintainer. limitations.md says so.
- **Fork PRs** get no comment and no SARIF (their token is read-only). The check still runs and decides.
- **Gate changes always take two PRs.** Code first, then the workflow that uses it. That is the price of the base-branch install.
- **Offline Semgrep.** p/secrets needs the internet; offline, Semgrep runs our local rules and the report says so.
- **Semgrep and Bandit are pinned by version, not by hash.** Their dependencies float.
- **CI fingerprints change every run.** There is no HMAC key in CI. A `SECUREGATE_HMAC_KEY` repo secret would make ids stable across runs; this is optional.
- **Closed demo PRs keep their commits on GitHub.** The tokens are fake ACME ones, so that is fine.

## Risks I check early (M1 and M2)

- **TruffleHog:**
  - `file://` with Windows paths
  - whether its temporary clone has the base commit when main has moved on
  - whether `VerificationError` exists in 3.97.9's JSON
- **Semgrep on Windows (beta):** its `.semgrepignore` behaviour, and how it fails when offline.
- **Bandit's `issue_text`** format for B105, B106 and B107.

If TruffleHog can't scan local paths on Windows, the local tests skip it with a reason, and CI (Linux) remains the real check. I'll tell you if that happens.

## Verification (done when)

1. `make check` is green at every milestone, with the skip reasons listed.
2. PR B (the Layer 2 workflow) passes its own four-scanner gate on GitHub.
3. `make demo-leak` gives a red check, a merge button locked by the ruleset, and a comment with the masked token, "rule 8: provider-keys", the ACME checklist and the history sentence.
4. `make demo-decoys` stays green, and the comment explains each warning and each ignored decoy.
5. `securegate doctor` is all green.
6. The leak and integration tests prove no planted value appears in any output.
7. The self-scan test still finds nothing in our own files.
