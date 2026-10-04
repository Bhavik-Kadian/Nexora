# SecureGate v0.1: Build Plan

> Approved on 2026-09-30. Environment answers: install GNU Make via winget, build `.venv` on Python 3.12, one commit per approved milestone, setuptools as the build backend.

## Context

SecureGate is a secret-scanning gate for Git repositories. It works in three steps:
1. **Find:** Gitleaks finds hardcoded secrets.
2. **Decide:** one readable file (`policy.yaml`) decides **block / warn / ignore**.
3. **Report:** findings are reported with the secret masked.

This session builds the core only: Gitleaks adapter, policy engine, masking, CLI, demo-repo generator, tests and docs. Later sessions add a dashboard, a CI merge gate and AI agents. So the Finding format and `findings.json` are designed to be read by those later pieces.

**Starting point.** `C:\Users\DARK\Documents\Nexora` is empty and not yet a Git repo. There is also an empty `Documents\SecureGate` folder, which I will not touch. Demo repos go to `C:\Users\DARK\Documents\securegate-demo` (`../securegate-demo`).

## Environment (checked, with your answers)

| Tool | Found | Action |
|---|---|---|
| Gitleaks | 8.30.1 (winget) | use as-is |
| Python | 3.14.7 only | `py install 3.12`, build `.venv` on 3.12 |
| GNU make | missing | `winget install --id ezwinports.make` (4.4.1) |
| Git | 2.55.0 | `git init -b main`, one commit per milestone after you approve it |
| Build backend | none | setuptools (install time only) |

**Gitleaks 8.30.1 facts I verified** (from the `--help` output and the v8.30.1 source):
- **Flags that exist:**
  - global: `--config --report-format --report-path --exit-code --no-banner --no-color --log-level --ignore-gitleaks-allow --gitleaks-ignore-path`
  - `git` command: `--log-opts --pre-commit --staged`
  - `--redact` also exists. We never pass it.
- **Exit codes:** `0` = no leaks, `1` = error, `--exit-code N` = leaks found, `126` = unknown flag.
- **Report:** the JSON report is written even when there are 0 findings (`[]`). Logs and the banner go to stderr.
- **Ways a scanned repo can hide findings:**
  - Gitleaks reads `.gitleaksignore` from the scanned folder.
  - It obeys `gitleaks:allow` comments unless we pass `--ignore-gitleaks-allow`.
- **Config syntax:** `[[allowlists]]` replaced `[allowlist]` in v8.25.0.
- **Default rule ids we rely on:**
  - AWS: `aws-access-token`, `aws-amazon-bedrock-api-key-long-lived`, `aws-amazon-bedrock-api-key-short-lived`
  - Stripe: `stripe-access-token`
  - GitHub: `github-pat`, `github-fine-grained-pat`, `github-oauth`, `github-app-token`, `github-refresh-token`
  - Other: `private-key`, `generic-api-key`
- **No rule** exists for passwords inside database URLs.

## File tree

```
Nexora/                         repo root
├── PLAN.md                     this plan
├── CLAUDE.md                   rules for Claude sessions (< 40 lines)
├── pyproject.toml              metadata, deps, console script `securegate`, pytest + ruff config
├── Makefile                    setup / test / lint / check / demo / scan-demo
├── .gitignore
├── .gitleaks.toml              Gitleaks default rules + ACME Pay rule
├── policy.yaml                 block / warn / ignore rules (first match wins)
├── docs/                       README, how-it-works, how-its-built, getting-started,
│                               testing, glossary, decisions
├── src/securegate/
│   ├── __init__.py             __version__ = "0.1.0"
│   ├── __main__.py             `python -m securegate`
│   ├── cli.py                  argparse: scan / demo-repo / version -> exit code
│   ├── errors.py               SecureGateError family (all mean exit 2)
│   ├── entropy.py              Shannon entropy
│   ├── mask.py                 masking, HMAC fingerprint, key loading, MaskedSecret
│   ├── finding.py              Finding dataclass + to_dict()
│   ├── confidence.py           0-1 confidence score (hook for a learned model later)
│   ├── policy.py               load + validate policy.yaml, decide()
│   ├── pipeline.py             raw candidates -> entropy -> policy -> masked Findings
│   ├── report.py               terminal table + findings.json
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── gitleaks.py         Gitleaks adapter (injected runner)
│   └── demo/
│       ├── __init__.py
│       ├── catalog.yaml        what to plant (owned by the Security Test Lead)
│       ├── catalog.py          load + validate catalog.yaml
│       ├── fakes.py            build fake secrets/decoys at runtime (seeded)
│       ├── generator.py        build the demo Git repo + ground_truth.csv
│       ├── scorecard.py        compare findings with ground truth
│       └── templates/          Jinja2 templates for the fake "DemoPay" app
└── tests/
    ├── conftest.py             test HMAC key, shared demo repo, helpers
    ├── fake_gitleaks.py        scripted fake runner (version/help/report)
    └── test_*.py               see "Tests"
```

## Modules: one job each

| Module | Job | Main API (type-hinted) |
|---|---|---|
| `cli.py` | Parse args, call one command, map the result or error to exit 0/1/2. No logic of its own. | `main(argv=None, runner=None) -> int` |
| `errors.py` | Error types. Any `SecureGateError` means exit 2 (fail closed). | `ConfigError`, `ScannerError`, `DemoError` |
| `entropy.py` | Shannon entropy in bits per character. Pure. | `shannon_entropy(value) -> float` |
| `mask.py` | The only place a raw value becomes something storable: a masked text plus an HMAC fingerprint. Also loads the key. | `protect(raw, key) -> MaskedSecret`, `mask_value`, `fingerprint`, `load_hmac_key(env, state_dir)` |
| `finding.py` | The Finding record. It accepts only a `MaskedSecret`, never a string. | `Finding`, `Finding.to_dict()` |
| `confidence.py` | "How sure are we this is real", from 0 to 1. Pure. | `estimate(rule_id, entropy) -> float` |
| `policy.py` | Load and validate policy.yaml. Decide per finding; the first matching rule wins. | `load_policy(path)`, `parse_policy(data)`, `decide(policy, *, rule_id, path, value, entropy) -> Verdict` |
| `scanners/gitleaks.py` | Run Gitleaks through an injected runner: detect its flags, build the command, read the temp report, return raw candidates. | `scan(...) -> ScanOutput`, `build_command(...)` (pure), `parse_report(text, target)` (pure), `subprocess_runner` |
| `pipeline.py` | The raw-value boundary. Candidates go in, masked Findings come out, and raw values never leave. | `run_scan(...) -> ScanResult`, `build_findings(candidates, policy, key)` (pure) |
| `report.py` | Terminal table, summary line, findings.json (atomic write). | `render_table`, `envelope`, `write_json` |
| `demo/catalog.py` | Validate catalog.yaml with plain-language errors. | `load_catalog(path) -> list[CatalogItem]` |
| `demo/fakes.py` | Build values in real-world formats at runtime from `random.Random(seed)`. | `build_plant(kind, file_type, rng, name, variant) -> Plant` |
| `demo/generator.py` | Build app files, planted lines, commit history and ground truth, with safety checks. | `generate(out, seed, force, catalog) -> DemoResult` |
| `demo/scorecard.py` | Score findings against ground truth: hits, misses, false alarms, wrong decisions. Pure. | `score(truth, findings)`, `format_scorecard(card)` |

## The Finding data format

Fields in `to_dict()` order:

| Field | Type | Example | Meaning |
|---|---|---|---|
| `id` | str | `"3f9a1c2b7d4e"` | first 12 hex chars of `fingerprint` |
| `rule` | str | `"aws-access-token"` | Gitleaks rule that matched |
| `detector` | str | `"gitleaks"` | scanner that found it |
| `file` | str | `"config/settings.py"` | path relative to the scanned folder, `/` separators |
| `line` | int | `9` | line where the value starts |
| `commit` | str or null | 40 hex | commit that added it (null in dir/staged mode) |
| `author` | str or null | `"Riya Demo"` | commit author name |
| `date` | str or null | `"2025-06-03T09:00:00Z"` | commit date |
| `masked_value` | str | `"AKIA****M7QX"` | 16+ chars: first 4 + `****` + last 4. Shorter: `****`. Non-printable characters show as `?`. |
| `fingerprint` | str | 64 hex | HMAC-SHA256 of the raw value |
| `entropy` | float | `3.921` | Shannon bits/char of the raw value |
| `confidence` | float | `0.9` | 0-1, from confidence.py |
| `severity` | str | `"critical"` | critical / high / medium / low / info, from the policy |
| `decision` | str | `"block"` | block / warn / ignore, from the policy |
| `reason` | str | `"provider-keys: ..."` | which policy rule matched, and why |
| `remediation` | str | `"Rotate the key ..."` | what to do next |

**How "only through masking" is enforced:**
- `mask.protect()` is the only way to get a `MaskedSecret`. Its constructor checks a token that is private to the module.
- `Finding` requires a `MaskedSecret` and raises `TypeError` for anything else. `id`, `masked_value` and `fingerprint` are read from it.
- The raw-value holder (`Candidate`) hides its value from `repr`.

**HMAC key:**
- Taken from `SECUREGATE_HMAC_KEY` (at least 32 characters).
- If that is unset, a random key is created once in `./.securegate/local.key`. It is created with mode 600, and the folder gets its own `.gitignore` containing `*`.

**findings.json:**

```json
{ "tool": "securegate", "version": "0.1.0", "schema_version": 1,
  "status": "fail", "exit_code": 1, "scanned_at": "2026-09-30T10:12:00Z",
  "target": "../securegate-demo", "mode": "repo", "range": null,
  "scanner": {"name": "gitleaks", "version": "8.30.1"}, "policy": "policy.yaml",
  "summary": {"total": 19, "block": 7, "warn": 5, "ignore": 7},
  "findings": [ ... ] }
```

On an error, the file has `status: "error"`, `exit_code: 2`, an `error` message and **no `findings` key**. A reader can't mistake it for a clean scan.

**Terminal:**

```
DECISION  RULE                FILE:LINE              VALUE
block     aws-access-token    config/settings.py:9   AKIA****M7QX
ignore    acme-pay-token      docs/payments.md:12    acme****xxxx
19 findings: 7 block, 5 warn, 7 ignore -> BLOCKED (exit code 1). Details: findings-demo.json
```

## policy.yaml

```yaml
# Rules are checked top to bottom. The FIRST rule that matches decides.
version: 1
rules:
  - name: placeholders
    when:
      value_matches: ['(?i)your_\w*_here', '(?i)changeme', 'EXAMPLE', '(?i)x{8,}', '(?i)dummy']
    decision: ignore
    severity: info
    reason: Looks like a placeholder or documentation example.
    remediation: No action needed.
  - name: tests-fixtures-docs
    when: { path_matches: ['**/tests/**', '**/fixtures/**', '**/docs/**'] }
    decision: warn
    severity: low
  - name: provider-keys          # ACME, AWS (3 ids), Stripe, private keys
    when: { rule_ids: [acme-pay-token, aws-access-token, ..., stripe-access-token, private-key] }
    decision: block
    severity: critical
  - name: github-tokens
    when: { rule_ids: [github-pat, github-fine-grained-pat, github-oauth, github-app-token, github-refresh-token] }
    decision: block
    severity: high
  - name: everything-else        # no `when` = matches everything
    decision: warn
    severity: medium
```

**How conditions combine:**
- Inside `when`, every condition must be true (AND).
- Inside one list, any single entry is enough (OR).

**The four conditions:**
- `value_matches`: a Python regex, searched anywhere in the raw value, in memory, before masking.
- `path_matches`: a glob. `**` means any number of folders (including none). `*` means any characters within one name.
- `rule_ids`: exact Gitleaks ids.
- `min_entropy`: true when entropy is at or above the number.

**Validation.** Any problem means exit 2, with the file, the rule number and a fix hint. It checks:
- YAML syntax and `version: 1`
- unknown keys, with a "did you mean ...?" suggestion
- unique rule names
- a valid decision and severity on every rule
- regexes that compile
- lists that aren't empty
- `min_entropy` is a number
- the last rule is a catch-all (it has no `when`)

## Gitleaks adapter (scanners/gitleaks.py)

1. Run `gitleaks version` and record the version. If Gitleaks is missing, exit 2 with install hints.
2. Run `gitleaks git --help` and `gitleaks dir --help` and collect the flags that exist. If a flag we need is missing, exit 2 and name it.
3. If the target contains `.gitleaksignore`, refuse with exit 2 (see Additions, #2).
4. Inside a `TemporaryDirectory`:
   - run the scan
   - read `report.json` (a UTF-8 JSON list)
   - turn it into `Candidate`s
   - let the directory be deleted

   The report is never logged or printed.
5. Interpret the Gitleaks exit code:
   - `0`: clean.
   - `99`: leaks found.
   - Anything else: exit 2, showing the last 3 stderr lines (truncated).
   - `99` with an empty or unreadable report: exit 2.

**Common flags on every scan:** `--config <.gitleaks.toml> --report-format json --report-path <tmp>/report.json --exit-code 99 --no-banner --no-color --log-level error --ignore-gitleaks-allow --gitleaks-ignore-path <tmp>`

| Mode | Command |
|---|---|
| repo | `gitleaks git <PATH> <common>` (full history) |
| range | `gitleaks git <PATH> --log-opts=<A..B> <common>`. The range is validated first: `ref..ref` or `ref...ref`, no spaces, no leading `-`. This blocks injecting `git log` options. |
| staged | `gitleaks git <PATH> --pre-commit --staged <common>` |
| dir | `gitleaks dir <PATH> <common>` |

**Reading the report.**
- Only these fields are read: RuleID, File, StartLine, Commit, Author, Date and Secret. Match is used as a fallback when Secret is empty.
- Match, Secret and Line are all treated as secret. Every other field is dropped.
- Paths are made relative to the target and use `/`.

**The real runner:**
- It finds `gitleaks` on PATH itself and never runs one from the current folder.
- It times out after 30 minutes (exit 2).
- Tests inject a fake runner instead, so they don't need the binary.

**`.gitleaks.toml`:**
- `[extend] useDefault = true`
- One rule `acme-pay-token`:
  - regex: `\bacme_(?:live|test)_[A-Za-z0-9]{32}\b`
  - keywords: `acme_live_`, `acme_test_`
  - no entropy filter, so the policy decides about placeholders
- One `[[allowlists]]` entry for virtualenv folders (`.venv/`, `venv/`). These hold third-party code, not our source.

## Demo generator

**catalog.yaml** is written for the Test Lead, with every field explained in comments:

```yaml
items:
  - kind: aws_key_pair        # what to plant (full list at the bottom of the file)
    file: config/settings.py  # where, inside the demo repo
    placement: current        # current | history-only (added early, deleted later)
    expected: block           # what SecureGate SHOULD decide: block | warn | ignore
    # name: AWS_KEYS          # optional variable name
    # variant: changeme       # optional, placeholder only: your_here | changeme | xxxx | dummy
    # note: free text         # optional
```

**Starting catalog.** This is my proposal; the Test Lead owns it after that.

| # | Kind | File | Placement | Expected |
|---|---|---|---|---|
| 1 | aws_key_pair | config/settings.py | current | block |
| 2 | stripe_live | payments/stripe_client.py | current | block |
| 3 | github_pat | .env | current | block |
| 4 | acme_token | web/checkout.js | current | block |
| 5 | private_key_block | deploy/server.key | current | block |
| 6 | db_url_password | config/app.yaml | current | warn |
| 7 | generic_password | Dockerfile | current | warn |
| 8 | stripe_live | scripts/migrate_customers.py | **history-only** | block |
| 9 | placeholder (your_here) | .env.example | current | ignore |
| 10 | placeholder (changeme) | docker-compose.yml | current | ignore |
| 11 | placeholder (xxxx, ACME-shaped) | docs/payments.md | current | ignore |
| 12 | aws_docs_example | docs/aws-setup.md | current | ignore |
| 13 | uuid | config/app.yaml | current | ignore |
| 14 | git_sha | web/version.js | current | ignore |
| 15 | base64_image | web/logo.js | current | ignore |
| 16 | minified_js | web/static/vendor.min.js | current | ignore |
| 17 | lockfile_integrity | package-lock.json | current | ignore |
| 18 | test_fixture_key | tests/fixtures/stripe_webhook.json | current | warn |

**Value formats.** Every value is built at runtime from a seeded random generator.

| Kind | Format |
|---|---|
| aws_key_pair | `AKIA` + 16 chars from [A-Z2-7], plus a 40-char secret (two lines, two ground-truth rows) |
| stripe_live | `sk_live_` + 24 letters/digits |
| test_fixture_key | `sk_test_` + 24 letters/digits |
| github_pat | `ghp_` + 36 letters/digits |
| acme_token | `acme_live_` + 32 letters/digits |
| private_key_block | PEM RSA block with a random base64 body; header and footer assembled from parts |
| db_url_password | `postgresql://demopay_app:<20 random chars>@db.demopay.internal:5432/demopay` |
| generic_password | 18 random characters, symbols included |
| aws_docs_example | AWS's published example pair, assembled from 5-character chunks |
| uuid | random v4 |
| git_sha | 40 random hex characters |
| base64_image | PNG data URI |
| minified_js | one long minified line containing hash-like constants |
| lockfile_integrity | `sha512-` + base64 |

**The app ("DemoPay", a fake payments service).**
- About 16 small files rendered from Jinja2 templates: Python, YAML, JS, JSON, a Dockerfile, docker-compose and Markdown.
- Each template has a marker line where the planted lines go (keeping the marker's indentation).
- Files that only the catalog mentions use a generic template for their file type.
- Kind/file combinations that make no sense are rejected with a clear message, for example a private key inside `.env`.

**Commit story.**
- Every commit uses the fixed author Riya Demo <riya@example.com>, fixed dates (2025-06-02 plus n days) and `-c commit.gpgsign=false`.
- Git runs isolated from your global and system config, so hooks, CRLF conversion and templates can't change the result.

Commits:
1. skeleton
2. configuration (+ root files such as `.env`)
3. one-off migration (the history-only files)
4. Stripe client
5. checkout page (`web/*`, `package*.json`)
6. Docker (+ `deploy/*`)
7. **remove** the one-off migration
8. tests and docs
9. supporting files (only if the catalog uses other folders)

Every file is written once and never edited later. That keeps ground-truth line numbers valid in both repo and dir mode. A history-only item must have its own file, and the whole file is deleted in commit 7.

**ground_truth.csv.**
- Columns: `file,line,commit,kind,is_secret,expected`. It contains **no values**.
- One row per planted value line.
- It lives in the demo folder, untracked and excluded via `.git/info/exclude`.

**Safety:**
- `--out` is resolved to an absolute path.
- Refuse (exit 2) if the output folder is inside any Git working tree, including this repo.
- Refuse a non-empty folder without `--force`.
- `--force` wipes **only** a folder that contains the generator's marker file `.securegate-demo`, and only inside that folder.

**Determinism:** the same seed gives the same commit SHAs and a byte-identical ground_truth.csv (tested).

## Tests (pytest)

**Convention:** tests never put a raw fake secret inside an `assert` expression, because pytest prints the operands. They compare masked values, counts or booleans. Failures report only kind and file:line.

| File | What it proves |
|---|---|
| test_smoke.py | package imports; `securegate version` exits 0 |
| test_entropy.py | `""` and `"aaaa"` give 0; `"ab"` gives 1; `"abcd"` gives 2; order doesn't matter |
| test_mask.py | 1-15 chars become `****`; 16+ show exactly 4+4 and never more than 8 original chars; the 15/16 boundary; non-printable characters become `?`; fingerprint equals stdlib HMAC-SHA256; `id` is the first 12 hex chars; the env key is used when set; a short env key gives exit 2; the key file is created once and reused; `.securegate/.gitignore` is created; mode 600 (skipped on Windows) |
| test_finding.py | a plain string is rejected (TypeError); `MaskedSecret` can't be built directly; `to_dict()` has the 16 fields in order and is valid JSON; the raw value never appears in `repr` or `to_dict` |
| test_policy.py | each default rule; first match wins (a placeholder in tests/ is ignored, a provider key in docs/ is warned); min_entropy; AND/OR logic; globs (`**/tests/**` matches `tests/a.py` and `x/tests/b.py` but not `contests/c.py`); invalid policies (bad YAML, unknown key, bad regex, bad decision, no catch-all, duplicate names, empty file) give exit 2; the shipped policy.yaml loads |
| test_gitleaks_adapter.py | uses the fake runner, no binary needed. clean → 0, leaks → 1, crash → 2, missing binary → 2; exit 99 with an empty, garbled or missing report → 2; exit code 126 → 2; a required flag absent from help → 2; `--config` always present and `--redact` never; per-mode flags; bad range strings refused; a `.gitleaksignore` in the target → 2; paths normalised |
| test_pipeline.py | raw candidates become masked Findings with entropy, verdict and confidence; no raw value appears in any `to_dict()` JSON; Candidate's repr hides the value; results sorted block → warn → ignore |
| test_cli.py | table and summary line; the findings.json envelope; the error envelope has no findings; invalid policy → 2 with a clear message; `--range` outside range mode → 2; missing policy or config file → 2; an unexpected exception → 2 |
| test_gitleaks_real.py | skipped without Gitleaks. One tiny tmp repo per mode (repo, range, staged, dir) holding a runtime-built ACME key → exit 1; a clean repo → 0. Proves our flags work with the installed binary. |
| test_self_scan.py | copies this repo's tracked and untracked-but-not-ignored files to tmp and scans them in dir mode: **zero findings** (enforces rule 2) |
| test_demo_generator.py | same seed gives the same HEAD SHA and CSV; a different seed gives different values; the author is Riya Demo; the history-only file is in history but not in HEAD; every ground-truth row points at the line holding its value; the refusals (non-empty folder, `--force` without marker, inside a Git repo), with nothing outside the output folder touched; catalog validation errors |
| test_leak.py | (a) always runs: a fake Gitleaks "finds" **every** planted value and the full CLI runs in-process. (b) The same through real Gitleaks in a subprocess. Both assert that no planted value appears in findings.json, stdout or stderr, and that the hidden middle of any 16+ char value doesn't either. |
| test_integration.py | skipped without Gitleaks. Generate, scan in repo mode, compare with ground_truth.csv, and **print** hits, misses, false alarms and wrong decisions (each with kind and file:line). It asserts only exit 1 and a valid findings.json, never the scores. It also checks that the history-only key is found in repo mode (matched by fingerprint and commit) and missed in dir mode. |

## Milestones

After each one: run `make check`, show you the output, wait. When you approve, I commit `M<n>: ...`.

1. **Skeleton**
   - Install make and Python 3.12; `git init -b main`.
   - pyproject, Makefile (setup/test/lint/check), CLAUDE.md, .gitignore, PLAN.md.
   - Package with `version` only, plus `test_smoke.py`.
   - Check that the Makefile works from both PowerShell and Git Bash.
2. **Masking, fingerprint, entropy, Finding:** errors.py, entropy.py, mask.py, finding.py, and their tests.
3. **Policy engine:** policy.py, policy.yaml, test_policy.py.
4. **Gitleaks adapter, .gitleaks.toml, pipeline, CLI**
   - scanners/gitleaks.py, confidence.py, pipeline.py, report.py, and the `scan`/`version` commands.
   - The adapter, pipeline, cli, real-Gitleaks and self-scan tests.
   - Then `securegate scan . --mode repo` on this repo (expect exit 0).
5. **Demo repo generator + integration test**
   - demo/* with templates and catalog.yaml, the `demo-repo` command, and the Makefile `demo`/`scan-demo` targets.
   - The generator, leak and integration tests.
   - Show the scorecard and `make demo && make scan-demo`.
6. **Docs**
   - The 7 pages in docs/, and set the pyproject readme to docs/README.md.
   - Walk through getting-started.md verbatim in a fresh clone.

## Additions beyond the spec (veto any)

1. `--ignore-gitleaks-allow` on every scan, so a `gitleaks:allow` comment can't bypass the policy.
2. **Refuse (exit 2) to scan a folder that has a `.gitleaksignore`.** Gitleaks would silently drop those findings before our policy sees them. The alternative is a warning.
3. `--force` only wipes marked demo folders, and demo output can't go inside any Git repo.
4. `SECUREGATE_HMAC_KEY` must be at least 32 characters. The `.securegate/` folder ignores itself in Git.
5. Gitleaks is found on PATH by our own code. Windows would otherwise run a `gitleaks.exe` planted in the scanned repo.
6. `--gitleaks-config` option (default `.gitleaks.toml`). A missing policy or config file gives exit 2.
7. A findings.json envelope with status, exit code, scanner version and summary.
8. Policy conditions go under `when:`; a catch-all last rule is required; unknown keys are rejected.
9. Catalog items can have `name`, `variant` and `note`. History-only items need their own file.
10. `confidence`: 0.9 for provider-specific rules; for generic ones, entropy/6 capped at 0.8. A placeholder for the learned model.
11. The virtualenv `[[allowlists]]` entry. Gitleaks' built-in list misses the Windows layout `.venv/Lib/...`.
12. `.gitignore` also gets `.pytest_cache/ .ruff_cache/ *.egg-info/ build/ dist/`.
13. Extra tests: self-scan, real-Gitleaks per-mode tests, and a leak test that runs even without Gitleaks.
14. Small helper modules: errors, confidence, report, demo/catalog, demo/fakes, demo/scorecard.

## Consequences of the spec worth knowing (building it as written)

- **Shared ids.** `id` comes from the fingerprint, so the same secret in two places shares one id. The id names the secret, not the spot.
- **Rule order.** Because the first match wins with this order, a real AWS key inside `tests/` or `docs/` only **warns**. Move the provider rules above the path rule if you don't want that.
- **make's exit code.** `make scan-demo`: securegate exits 1, but GNU make always exits 2 when a recipe fails (it prints `Error 1`). SecureGate prints its own exit code in the summary line.
- **Expected misses.** Gitleaks has no rule for DB-URL passwords, and its generic rule misses passwords that contain symbols. Expect misses in the scorecard. They'll be reported, not tuned away.
- **Key file on Windows.** `chmod 600` doesn't work on Windows, so there the key file relies on your user-profile folder's permissions.
- **Temp report on disk.** As specified, the raw report sits briefly in a private temp folder. `--report-path -` (stdout) would keep it off disk entirely, since Gitleaks' logs go to stderr. Tell me if you'd prefer that.

## Verification (done when)

1. `make check` is green: ruff check, ruff format --check and pytest, with skip reasons listed.
2. `make demo && make scan-demo`: a masked table, and a summary saying "exit code 1".
3. `securegate scan . --mode repo` in this repo exits 0 (after the milestone commits).
4. A fresh clone into a scratch folder, following docs/getting-started.md word for word, reaches a first scan.
5. The self-scan test proves no key-shaped strings in our own files.

---

# Layer 2: the merge gate (four scanners, one verdict)

> Approved on 2026-10-04. Answers: create the GitHub repo with gh (ask first), install Semgrep and Bandit into .venv and TruffleHog with `make scanners`, gh via winget, commit the open dashboard work first, and keep installing SecureGate and its rules from the base branch in the workflow.

Every pull request to main is scanned on GitHub by Gitleaks, TruffleHog, Semgrep and Bandit. Their findings merge into one verdict decided by `policy.yaml`; the pull request gets a comment, a SARIF upload and a job summary, and a red check locks the merge button.

**Rollout in two pull requests**, because the workflow installs SecureGate from the base branch (a pull request cannot change the code that judges it):
- PR A: the engine (milestones 1 to 3), judged by the Gitleaks-only gate already on main.
- PR B: the new workflow (milestone 4), judged by Layer 2 code from main, so it passes its own four-scanner gate.
- PR C: the demo kit and docs (milestones 5 and 6).

**Milestones**, each ending with `make check`, a stop for review, and one commit:
1. TruffleHog adapter, merge logic, policy rules (rule numbers, `validity`)
2. Semgrep and Bandit adapters, `rules/securegate-risky.yml`
3. Outputs: PR comment, SARIF 2.1.0, job summary
4. The workflow `.github/workflows/secret-gate.yml`
5. Demo kit (`demo-pr`, `demo-cleanup`, `doctor`, `ci-report`)
6. Docs (`merge-gate.md`, `demo-script.md`, `limitations.md`, CODEOWNERS)

**Policy table rules in this layer** (first match wins): 1 verified-live (block, critical), 3 placeholders (ignore), 7 tests-fixtures-docs incl. `*.md` and `*.example` (warn, medium), 8 provider-keys by value format (block, high), 9 test-mode-keys (warn, medium), 10 hardcoded-passwords (warn, medium), 13 risky-handling (warn, low), 14 everything-else (warn, medium). Rules 2, 4, 5, 6, 11 and 12 come in later sessions.

## TruffleHog 3.97.9 facts I verified (milestone 1)

From `trufflehog --help`, `trufflehog git --help` and real runs on a throwaway repository:
- **Installed** from the GitHub release `trufflehog_3.97.9_windows_amd64.tar.gz`, checked against `trufflehog_3.97.9_checksums.txt` (SHA-256 `d8a2807f...7f93f`, pinned in the workflow). No winget package exists.
- **Switches are printed as `--[no-]json`** by kingpin, so the flag probe accepts that spelling.
- **Flags used:** `git <uri> --since-commit <base> --branch <head> --json --no-update --no-ignore-tag --fail-on-scan-errors --results=verified,unknown,unverified [--no-verification] [--config .trufflehog.yaml]`. Never `--fail` (exit 183 on findings).
- **`--version`** and **`--help`** print to stdout with exit code 0. An unknown flag gives exit code 1.
- **Windows:** `file://C:/Users/...` works. TruffleHog clones the repository into a temporary folder first; the clone contains a base commit that main has moved past, so ranges whose base is not an ancestor work.
- **Output:** one JSON object per line on stdout; logs are JSON lines on stderr (`--log-level=-1` silences them). Fields: `SourceMetadata.Data.Git.{commit,file,email,repository,timestamp,line,repository_local_path}`, `DetectorType`, `DetectorName`, `DecoderName`, `Verified`, `VerificationFromCache`, `Raw`, `RawV2`, `Redacted`, `ExtraData`, `StructuredData`, `SecretParts`; `VerificationError` only when a check failed. A custom detector reports `DetectorName: "CustomRegex"` with its name in `ExtraData.name`.
- **Errors:** with `--fail-on-scan-errors`, an unknown `--since-commit` ends with exit code 1 and an error-level log line.
- **Timestamps** look like `2026-10-04 17:30:45 +0000`; `email` is `Name <address>`.
