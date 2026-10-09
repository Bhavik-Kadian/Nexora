# Live checks: ACME Pay, an invented provider (built after Layer 2)

> **Working note, kept as it was written.** The approved plan for live checks: ACME Pay, an invented payment provider on Azure, and policy rule 2. Written on 2026-10-05. **Never built**: the project closed first. See [Roadmap](../roadmap.md). The pages in [docs/](../README.md) describe SecureGate as it is; [History](README.md) lists every note.

## Context

Layer 2 can say "this looks like a key", but not "this key works right now". To show "verified live" and "revoked" with zero real credentials, we build **ACME Pay**, an invented payment provider that issues and revokes `acme_live_` keys.
- SecureGate asks it directly whether a found ACME key is live.
- TruffleHog's ACME detector asks the same endpoint.
- New policy **rule 2** lets a pull request pass, marked **resolved**, once the leaked key is revoked *and* gone from every file at head.

**When.** Approved order: I finish Layer 2 (M2–M6) first, then build this as four milestones. Part 4 extends Layer 2's demo kit (`demo-pr`, `demo-script.md`, the workflow).

**What's already in place** (reused, not rebuilt):
- `.trufflehog.yaml` has the ACME detector, without a verify endpoint.
- Findings carry `validity`, and the policy has a `validity` condition and rule 1.
- Merging keeps the strongest validity (`src/securegate/merge.py`).
- `report_view.LIVE_CHECK` has the labels.
- The ACME token format is in `demo/token.py`.
- The masking shape is in `mask.py`.
- The dashboard's `SECURITY_HEADERS` and `tokens.css` are in `ui/`.

**Accounts (checked today):**
- **GitHub:** gh is logged in as **Bhavik-Kadian**, with the `repo` and `workflow` scopes, so it can push branches and workflow files.
- **The repo already exists:** `Bhavik-Kadian/SecureGate` is public and holds one "Initial commit" with a README (`# SecureGate`). For Layer 2's PR A, I therefore won't run `gh repo create`. I'll add it as `origin`, join the two histories once with `git merge --allow-unrelated-histories` (non-destructive), and turn that README into a short pointer to `docs/`. I'll ask before pushing.
- **Azure:** you have no Azure login yet. At milestone 4:
  1. You create an Azure account. The free account needs a phone and a card check; Azure for Students needs a school email and no card. Both let you sign in with GitHub.
  2. I install the Azure CLI (`winget install --id Microsoft.AzureCLI`, 2.90.0).
  3. You run `! az login`.
  4. I deploy to the free **F1** tier, asking before each Azure change.

## 1. `acme_provider/`: Flask, separate from the engine (never imports `securegate`)

**Files:**

| File | Job |
|---|---|
| `app.py` | `create_app(config)` |
| `wsgi.py` | the Gunicorn entry, `acme_provider.wsgi:app` |
| `config.py` | settings from environment variables |
| `keys.py` | issue, HMAC, mask |
| `store.py` | stdlib `sqlite3` |
| `templates/` | the login and keys pages |
| `static/provider.css` | uses only `var(--…)`, like `app.css` |
| `requirements.txt` | Flask only, for Azure |
| `__main__.py` | local run on 127.0.0.1:5050 |

**Settings** (environment variables):
- `ACME_ADMIN_TOKEN`, `ACME_HMAC_KEY` and `ACME_SESSION_KEY`, each at least 32 characters.
- `ACME_DASHBOARD_PASSWORD`.
- `ACME_DB_PATH`. On Azure this is `/home/data/acme-pay.sqlite3`; only `/home` survives restarts.
- A missing or short value refuses to start, with a clear message. For local use, `make provider` creates missing values once in a gitignored `.acme-provider/` folder and says where they are. It never prints them.

**Stored data.** The plaintext key is never stored or logged.
- `keys`: `id` (12 hex), `fingerprint` (HMAC-SHA256), `masked` (`acme****wxyz`, SecureGate's masking shape, so the PR comment and the dashboard show the same text), `label`, `status` (live or revoked), `issued_at`, `revoked_at`.
- `checks`: `time`, key id or fingerprint prefix, result.

**API:**

| Endpoint | Who | Result |
|---|---|---|
| `POST /api/keys` | `Authorization: Bearer <admin token>`, compared in constant time | `201 {"key","id","masked","status":"live","issued_at"}`. The only response that ever holds a key. |
| `POST /api/keys/revoke` | admin | Body `{"id"}` or `{"key"}`. Answers `200 {"id","status":"revoked","revoked_at"}` (idempotent), or 404. |
| `POST /api/verify` | public | Accepts `{"key": "..."}` (SecureGate) and TruffleHog's body (see section 2). Answers `200 {"status":"live"}`, `401 {"status":"revoked"}`, `401 {"status":"invalid"}`, or `400` when malformed. Each check is logged: time, key fingerprint id, result. |
| `GET /healthz` | public | `200` with no data. For `doctor`, and to wake the sleeping F1 app. |

**Dashboard (`GET /`):**
- A login form with the password from the environment.
- A signed session cookie: HttpOnly, Secure, SameSite=Strict.
- A keys table: masked key, status badge, issued, revoked, and a **Revoke** button (a form with a CSRF token).
- A "recent checks" list for incident notes.
- Logout.
- SecureGate's security headers, with no scripts and `form-action 'self'`.
- Styled with **SecureGate's `tokens.css`**. The deploy zip copies that one file, and a test checks the copy is byte-identical.
- Werkzeug's `ProxyFix`, so cookies are Secure behind Azure's TLS proxy.

**Make targets:** `make provider` runs it locally. `make provider-zip` builds `dist/acme-provider.zip` (the package, `tokens.css` and `requirements.txt`).

## 2. Live checks in the engine: `src/securegate/verify/acme.py`

**What gets sent, and where:**
- Only values in the ACME **live** format go out, and only to `ACME_VERIFY_URL` + `/api/verify`.
- The request is `POST {"key": ...}`, built in memory. It never follows redirects.
- HTTPS is required, except for `http://127.0.0.1` and localhost (the local provider and tests).
- Timeout 10 s, with one retry on a timeout or connection error. F1 wakes slowly.

**Answer → validity:**

| Provider answer | Validity |
|---|---|
| 200 `live` | `verified` |
| 401 `revoked` | `revoked` (new) |
| 401 `invalid` | `invalid` (new) |
| timeout, network error, other status, unreadable JSON | `unknown`, which never passes on its own |
| no `ACME_VERIFY_URL`, or `--no-verification` | `not_checked` |

- The validity order becomes: verified, unknown, revoked, invalid, unverified, not_checked. New labels: "Revoked by the provider" and "Invalid: never issued".

**Source of truth.** The direct answer sets the validity of *every* finding of that key, whether Gitleaks or TruffleHog found it, and overrides TruffleHog's own answer.
- One request per distinct key per scan.
- The pipeline applies it before the policy decides, so raw values stay inside the pipeline.
- The HTTP call is injected, so tests can replace it.

**TruffleHog.** When `ACME_VERIFY_URL` is set, SecureGate writes a private temp copy of `.trufflehog.yaml`. Its ACME detector gets TruffleHog's documented verify block:
```yaml
verify:
  - endpoint: <ACME_VERIFY_URL>/api/verify
    unsafe: true            # only for an http:// local provider
    successRanges: ["200"]  # verified
    rotatedRanges: ["401"]  # rotated
```
- TruffleHog 3.97.9's code posts `{"ACME Pay token": {"token": ["<match>"]}}`, a **list**, although its guide shows a plain string. The provider accepts both.
- A test with the real TruffleHog against a local provider pins what it actually sends.

## 3. Policy rule 2 (from the policy table)

```yaml
- number: 2
  name: revoked-and-removed
  when: {validity: [revoked], at_head: false}
  decision: ignore
  severity: info
  resolved: true
  reason: The provider revoked this key, and it is no longer in any file, so nobody can use it.
```

**The new condition `at_head`:**
- It is computed only for revoked keys, with `git grep -q -F -f - <head>`. The key goes in on stdin, never on a command line, and nothing is printed.
- Head is the end of the range (range mode) or HEAD (repo mode). In dir and staged modes, the key is in a file by definition.
- If it can't be determined, it counts as present.

**Marking it resolved.** A new rule key, `resolved: true`, is allowed only with `ignore`. The finding then gains `resolved`. The comment, summary and dashboard show **RESOLVED**; SARIF leaves it out; the exit code is pass. I'm not adding a fourth decision, because counts, badges and exit codes all assume three.

**How it sits among its neighbours:**
- Verified: rule 1 blocks first.
- Revoked but still in a file: rule 8 keeps blocking.
- Invalid or unknown: rule 8 blocks.

## 4. Workflow and demo

- **Workflow:** the scan step gets `env: ACME_VERIFY_URL: ${{ vars.ACME_VERIFY_URL }}` (set with `gh variable set`). The base-branch SecureGate ignores an env var it doesn't know, so this ships **in the same PR** as the engine.
- **`securegate demo-pr leak --live`:**
  - It issues a key through `POST /api/keys`, with `ACME_ADMIN_TOKEN` from the environment.
  - It writes the key straight into `demo-app/payments.py` and never prints it. It prints only the masked form, so you can find the key in the dashboard.
- **`securegate demo-rerun`** and **`make demo-rerun`:** re-run (with `gh run rerun`) the latest secret-gate run on a `demo/*` branch. It refuses while that run is still going.
- **`doctor` adds two checks:** the `ACME_VERIFY_URL` variable exists on GitHub, and `GET /healthz` answers. The second also wakes the provider.
- **`docs/demo-script.md`** gets the three-step flow, each step with its command, what the judges see, one line to say, and the time:
  1. `leak --live`: red, "verified live", critical.
  2. Delete the line: still red, because the key is live in the history.
  3. Revoke it in the ACME dashboard, then `make demo-rerun`: green, "rule 2", RESOLVED.

## 5. Deploy: `docs/acme-provider.md` (from Microsoft's current docs: Python is Linux-only, run under Gunicorn)

1. Create the account, install the CLI, and sign in (`az login`).
2. `az group create --name acme-pay-rg --location centralindia`
3. `az appservice plan create --name acme-pay-plan --resource-group acme-pay-rg --sku F1 --is-linux`
4. `az webapp create --name <unique-name> --resource-group acme-pay-rg --plan acme-pay-plan --runtime "PYTHON:3.12"`
5. `az webapp config appsettings set ... --settings @.acme-provider/azure-settings.json`. That file is generated locally and gitignored: `SCM_DO_BUILD_DURING_DEPLOYMENT=true`, the four secrets and `ACME_DB_PATH`. Secrets never go on a command line or into the repo.
6. `az webapp config set ... --startup-file "gunicorn --bind=0.0.0.0 --timeout 600 --workers 1 acme_provider.wsgi:app"`
7. `make provider-zip`, then `az webapp deploy --resource-group acme-pay-rg --name <app> --src-path dist/acme-provider.zip --type zip`
8. `gh variable set ACME_VERIFY_URL --body https://<app>.azurewebsites.net`

**Free tier note.** F1 sleeps after about 20 idle minutes, and the first request then takes 10–30 s. Open the dashboard, or run `securegate doctor`, a minute before a demo.

**Gunicorn.** Azure's image runs Gunicorn itself. If it turns out to be missing, I stop and ask before adding it (CLAUDE.md rule 6). I'll check every command against `az <cmd> --help` before writing it into the doc.

## Milestones (each: `make check`, show you, wait, one commit)

1. **The provider**
   - the app, API, dashboard and store; `make provider`; `make provider-zip`
   - tests: issue, verify, revoke, auth required, CSRF; the plaintext key appears in **none of** the SQLite file, the logs or the dashboard HTML
2. **Engine live checks**
   - `verify/acme.py`, the new validity values, `at_head`, rule 2 and `resolved`, the TruffleHog verify config
   - the outputs show live, revoked and resolved
   - tests:
     - the verifier against a fake local HTTP server: live, revoked, invalid, timeout → unknown, no redirect followed, and nothing sent for non-ACME keys
     - rule 2 against each neighbouring rule
     - the real TruffleHog against the local provider
     - the leak test extended to the provider's logs and dashboard
3. **Demo and workflow**
   - `vars.ACME_VERIFY_URL`, `demo-pr leak --live`, `demo-rerun`, the doctor checks
   - `demo-script.md`, and updates to `merge-gate.md`, `CLAUDE.md`, `decisions.md` and the PDFs
4. **Deploy**
   - your Azure account and `az login`, the F1 deploy, `gh variable set`
   - `docs/acme-provider.md` written while doing it
   - the three-step flow on GitHub against the deployed provider
   - then **one PR** (engine and workflow)

## Additions beyond the spec (veto any)

1. **Only live ACME keys are ever sent.** `acme_test_` keys never leave the laptop.
2. **`GET /healthz`**, for `doctor` and for waking the app.
3. **A "recent checks" list on the dashboard**, for incident notes.
4. **The provider masks keys exactly like SecureGate.**
5. **A `resolved` field and badge**, instead of a fourth decision.
6. **The verifier refuses redirects, and retries once on a timeout.**
7. **`at_head` reads the key from stdin.**
8. **Secrets reach Azure through a gitignored settings file**, never through command arguments.

## Consequences worth knowing

- **`/api/verify` is public, like a real provider's API.** Anyone can test whether an ACME key is live. That's harmless for an invented provider, and every check is logged.
- **A sleeping F1 app can make a check time out.** That gives `unknown`, which stays red and never passes. Warm the app up before a demo.
- **SQLite on `/home`** is fine for one F1 instance. A bigger setup would need a real database.
- **The F1 tier stays free**, but the Azure account itself needs a card check, unless you use Azure for Students.

## Verification (done when)

1. `make check` passes at every milestone.
2. Locally: `make provider`, then the live flow end to end against `http://127.0.0.1:5050`, with real Gitleaks and TruffleHog.
3. Deployed: on GitHub against the Azure provider:
   - `leak --live` gives red, "verified live", critical
   - after deleting the line, it's still red
   - after revoking and `make demo-rerun`, it's green, "rule 2", RESOLVED
4. `docs/demo-script.md` and `docs/acme-provider.md` are updated, and their PDFs are rebuilt.
