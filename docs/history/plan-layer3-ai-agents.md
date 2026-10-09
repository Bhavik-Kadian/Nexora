# Layer 3: three AI agents (triage, fix, incident) on Azure AI Foundry

> **Working note, kept as it was written.** The approved plan for Layer 3: three AI agents (triage, fix, incident) on Azure AI Foundry. Written on 2026-10-07. Built on 2026-10-07 (pull requests #7 and #8). The pages in [docs/](../README.md) describe SecureGate as it is; [History](README.md) lists every note.

## Context

You asked for "the 3 agentic AI" in SecureGate and chose: a **triage** agent, a **fix** agent and an **incident/rotation** agent, running **in the merge gate and locally**, after Layer 2. Layer 2 is finished: PR #5 is green and waiting for you to merge it.

Your first choice of AI service, GitHub Models, **was shut down on 2026-07-30**. GitHub's docs say so, and its old API now answers with a plain "OK" placeholder. You then chose **Azure AI Foundry**, Microsoft's official replacement. The same Azure account will also serve the live-checks layer later.

What you get: for every scan, the agents explain each finding, suggest the code fix, and write the response plan for a leaked key. This shows up in the PR comment, the dashboard, the menu and the CLI. The agents **advise only**: `policy.yaml` still decides, the exit codes do not change, and no agent ever sees a whole secret.

## Ground rules

1. **Advice only.** The gate's result never depends on AI. If Azure fails or is not set up, the advice says "not available" and the exit code stays exactly what the policy decided. In the workflow, the agents step runs after the exit code is saved, with `continue-on-error`.
2. **No whole secret reaches Azure.**
   - The model gets masked findings, plus code lines in which each finding's value is removed **exactly**: the token whose HMAC equals the finding's fingerprint (`mask.fingerprint`, with the key that made the report) becomes `<SECRET>`.
   - On top of that, everything secret-shaped is removed: the policy's value patterns, high-entropy tokens (`entropy.shannon_entropy`), and every string literal on a finding's line.
   - If a value can't be located exactly, that finding's code lines are **not sent at all** (fail closed).
3. **Model output is untrusted.**
   - It must match a strict JSON schema, or it is dropped.
   - It is sanitized: secret-shaped tokens become `****`; HTML, links and `@mentions` are removed; lengths are capped.
   - It is rendered only through the existing escaping (`outputs/markdown.safe`, Jinja autoescape), under the label "AI advice: the policy decided, not the AI".
4. **Prompt injection is contained.**
   - Pull request code is untrusted input.
   - The agents only get **read-only tools** that return redacted data, and at most 6 tool calls each.
   - No tool can write, run commands or reach the network. The worst a hijacked agent can do is write misleading advice text, which cannot change the check.
5. **No new dependency.** Python's own `urllib` makes the HTTPS calls.
   - The key comes from `SECUREGATE_AI_KEY` (env or GitHub secret) or `.securegate/ai.json` (Git ignores that folder, like `local.key`).
   - It is never printed or logged. Errors name the HTTP status only.
6. **Tests never call Azure.** A fake model is injected that plays scripted tool calls and answers, like the fake Gitleaks. One optional live test is skipped when there is no key.

## Design

### Azure client: `src/securegate/agents/client.py`
- `POST {endpoint}/openai/v1/chat/completions` with header `api-key`. The body holds the deployment name, the messages, the tools (`parallel_tool_calls: false`), `response_format` as a strict `json_schema`, a `max_completion_tokens` cap, and low reasoning effort (checked on the real model in M5).
- 60-second timeout. 429 and 5xx are retried at most twice, respecting `Retry-After`. Anything else raises `AgentUnavailable`.
- Settings: `SECUREGATE_AI_ENDPOINT` (`https://<resource>.openai.azure.com`), `SECUREGATE_AI_DEPLOYMENT` (default `gpt-5.4-mini`) and `SECUREGATE_AI_KEY`. Environment variables override `.securegate/ai.json`.
- Why **gpt-5.4-mini**: it is generally available; a new subscription can deploy it until 2027-03-17 (gpt-4.1-mini and gpt-5-mini are already closed to new subscriptions); it retires 2027-09-21.

### Read-only tools and the loop: `agents/tools.py`, `agents/loop.py`
**Tools:**
- `list_findings`: masked rows only.
- `code_context(id)`: ±6 lines at the finding's commit, read with `git show` and redacted as in rule 2.
- `policy_rule(n)`: from `policy.load_policy`.
- `provider_steps(id)`: `outputs/rotation.provider_for` and `ui/fixes.REVOKE_AT`, so the incident agent is grounded in our checklists instead of inventing steps.
- `git_facts(id)`: commit, author, date, and whether the commit is in the pull request only or already on main.

**Loop:** model → validated tool calls → results → … → final structured answer. Limits: at most 6 tool calls and 20 findings per agent. A bad answer is asked for again once, then the agent's status is `failed`.

### The three agents: `agents/triage.py`, `fix.py`, `incident.py`
- **Triage.** For each block or warn finding:
  - `verdict` (likely real / likely false alarm / needs a human), `confidence`, `why`, `next step`.
  - Shown next to the policy's decision. When the agent disagrees, it says so: "the policy still blocks it; to change that, edit policy.yaml in a separate PR".
- **Fix.** For each single-line finding in a code file:
  - The environment variable's name, the replacement line (the value replaced by an environment read), the import it needs, and why.
  - SecureGate checks that the indentation is the same, nothing secret-shaped is left, and only that one line changes. Multi-line values, such as PEM keys, get advice but no edit.
- **Incident.** For the blocked findings:
  - Severity; exposure (is the pull request public, how long has the key been out since its commit date, who could see it).
  - Ordered steps: revoke and rotate at the provider (grounded on `provider_steps`), check the provider's logs for use since that date, clean the history only when needed, and who to tell.
  - Later it can call ACME Pay's revoke endpoint, once the live-checks layer exists.

### Where the advice goes
- **findings.json** gets an optional `advice` section. It is additive, so `schema_version` stays 1. It holds status `ok|skipped|failed`, a note, the model, the time, and triage, fixes and incident.
  - `securegate agents --report F [--only …] [--comment F --summary F]` writes it, and re-renders the comment and summary through `write_outputs`.
  - `ui/report_view.load_report` validates it: types, lengths, finding ids, and the sanitizer runs again. Bad advice is **withheld with a note**, and the rest of the report still shows.
- **PR comment and summary** (`outputs/templates/report.md.j2`) get a section "AI advice (the policy decided, not the AI)":
  - one triage line per row;
  - fix suggestions as code blocks, with no secret in them;
  - the incident plan folded away;
  - or one line saying why there is no advice.
- **Dashboard** (read-only, no JavaScript, as before):
  - the finding page gets "AI triage" and "AI fix suggestion" panels next to "How to fix";
  - a new `/incident` page shows the plan;
  - the overview shows the advice status.
- **Menu**, so nothing needs typing:
  - a new main choice **A "AI agents"**: set up (endpoint, deployment, and the key typed hidden with `getpass`), ask about the last scan, open the incident plan, check the connection;
  - after scans 1, 2 and 4: "Ask the AI agents about these findings? [Y/n]" (shown only once AI is set up), saying exactly what is sent;
  - the gate screen (9) gains "Let the fix agent open a fix pull request for the last demo".
- **CLI:** `securegate agents`, `securegate ai-setup` (the menu runs it) and `securegate agent-fix --pr N`.
- **doctor:** AI checks. Settings present (SKIP when not set up); a tiny test call that sends no repository data; the deployment answers.

### Fix pull request, from the laptop only: `agents/fix_pr.py`
`agent-fix --pr N`:
1. Refuses a dirty working tree, a missing gh login or a fork's pull request. The checks are reused from `github.py` and `demo/pull_requests.py`.
2. Reads the pull request's head with `gh pr view`.
3. Makes a temporary worktree on a new branch: `demo/fix-<scene>-<time>` for demo pull requests (so `demo-cleanup` removes it too), `securegate-fix/<branch>-<time>` otherwise.
4. **Scans the pull request's range locally**, so the fingerprints come from your own key and it never trusts a downloaded report.
5. Asks the fix agent, checks and applies the line edits, and commits. The laptop gate stays on: the change only removes secrets.
6. Pushes, then runs `gh pr create --base <PR's branch>`. The body says the key is still in the history, so revoke it, and links to the incident plan.
7. It prints what changed only as "line 3: `acme****x9Qz` → `os.environ["ACME_PAY_API_KEY"]`", never a raw diff.

When the key exists only in an older commit (the deleted-later scene), it opens nothing and says: revoke the key.

The merge gate itself stays read-only (`contents: read`). In CI, a fix is a suggestion in the comment.

### Workflow (second PR, after the code is on main)
- A step "Ask the AI agents" runs after the scan and before the summary, comment and artifact. It runs only when the exit code is 0 or 1 and the pull request is not from a fork, with `continue-on-error` and `timeout-minutes: 3`.
- It gets `SECUREGATE_AI_KEY` from secrets, and the endpoint and deployment from repository variables.
- Fork pull requests get no secrets, so their comment says the advice was not available. The check still decides as before.

## Milestones (after each: `make check`, show you the output, wait; one commit each)

1. **Safety core:** redaction (exact by fingerprint, then generic), the output sanitizer, the `advice` schema and its validation in `load_report`, and the fake model. Leak tests: values planted at runtime never appear in a model request (recorded by the fake transport), the advice, findings.json, the comment, the summary, the dashboard or the menu.
2. **Client, tools, loop and the three agents, plus `securegate agents`.** Tests: scripted tool calls; limits; malformed answers; Azure down (status `failed`, exit codes unchanged); prompt injection planted in code comments (the tools stay read-only and the advice is labeled).
3. **Into the UI:** the comment and summary section, dashboard panels and `/incident`, menu choice A and the after-scan offer, `ai-setup` (hidden key, `.securegate/ai.json`), and the doctor AI checks.
4. **Fix pull request:** `agent-fix --pr N` and the gate screen entry. Tests use a bare local origin, the fake gh and the fake model, the same setup as `tests/test_demo_kit.py`.
5. **Connect Azure, with you:**
   - You create the account (Azure for Students: school email, no card), a Foundry resource and a `gpt-5.4-mini` deployment, in the portal; I give the exact clicks.
   - You run menu A → set up, then doctor should show every line as PASS.
   - A live run on the demo project; I tune the prompts.
   - Docs: new `docs/agents.md`, plus how-it-works, merge-gate, demo-script (scene 6, the agents), presenting, limitations, decisions, glossary, testing, how-its-built and getting-started; PDFs.
   - Then **PR D** (the code).
6. **Workflow:**
   - You add the secret and the two variables (GitHub → Settings → Secrets and variables), since the permission system won't let me.
   - **PR E** adds the agents step, and must show AI advice in its own comment.

## Reused code
- From `mask.py`: `fingerprint`, `mask_value`, `load_hmac_key`, `default_state_dir`.
- `policy.load_policy` (value patterns), `entropy.shannon_entropy`.
- `outputs/rotation.provider_for`, `ui/fixes.REVOKE_AT`, `outputs/markdown.safe`, `outputs.write_outputs`.
- `ui/report_view.load_report`, `ci_report.download_report`.
- From `github.py`: `Tools`, `check`, `run`, `origin_slug`, `gh_logged_in`.
- The `demo/pull_requests.py` worktree pattern and `is_demo_branch`.
- From `menu/app.py`: `Menu.perform`, `choice_line`, `yes`, `securegate`.
- In tests: the `FakeGh` and `Origin` fixtures and the `helpers.fake_*` builders.

## Choices made for you (veto any)
1. The advice lives inside findings.json, so the comment, the dashboard and `ci-report` all carry it.
2. Fix pull requests come only from your laptop, with your gh login; the gate keeps its read-only token.
3. The key is kept locally in `.securegate/ai.json` (Git-ignored), like the fingerprint key. A Windows credential store would need a new package.
4. The model is gpt-5.4-mini; the deployment name can be changed.
5. The menu's "Ask the AI agents?" defaults to Yes once AI is set up, and says what is sent: masked findings and code lines with every secret removed.

## Risks
- Azure for Students may not have quota for gpt-5.4-mini in every region. M5 checks quota first; the fallback is another region, or a free Azure account.
- Structured outputs on gpt-5.4-mini: checked in M5. The fallback is JSON mode plus our own validation, which runs anyway.
- Cost is small and capped: at most 3 agents × 7 model calls, and 20 findings per scan.

## Verification
- `make check` is green at every milestone. The leak tests above cover every place advice can appear.
- M5, live: menu A → set up; doctor shows every line as PASS; menu 1 → ask the agents; the dashboard shows triage, fix and the incident plan; `agent-fix` on a demo leak pull request opens a fix pull request.
- M6: PR E's own comment shows the AI section. A run without the secret shows "AI advice: not set up", and the check result is unchanged.
