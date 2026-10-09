# Decisions

The choices behind SecureGate, from v0.1 to the close-out at v1.0.0: what we chose, why, and what we rejected. Add an entry whenever you make a choice that someone might question later. Words in bold are explained in the [Glossary](glossary.md).

## 1. Gitleaks finds, SecureGate decides
- **Chose:** **Gitleaks** finds candidate secrets; our own `policy.yaml` decides what happens to them.
- **Why:** Gitleaks already knows many key formats and is widely used. What we add is the decision and the safe reporting.
- **Rejected:** writing our own detection rules for every provider; TruffleHog in v0.1 (it joined later as a second finder, see 45).

## 2. One readable policy, first match wins
- **Chose:** rules checked from top to bottom; the first rule that matches decides.
- **Why:** anyone can read the file and predict the result.
- **Rejected:** scores and weights (hard to predict); several policy files.

## 3. The last rule must match everything
- **Chose:** a policy without a final catch-all rule, or with unknown words in it, is refused (exit code 2).
- **Why:** every finding gets a decision, and a typo can never switch a rule off silently.
- **Rejected:** a hidden default decision.

## 4. Rule order as specified
- **Chose:** the order of SecureGate's policy table: 1 a key confirmed live, 3 placeholders, 7 tests, fixtures, docs, Markdown and example files, 8 live provider keys, 9 test-mode keys, 10 passwords in the code, 13 risky handling, 14 everything else. (Until Layer 2 it was placeholders, tests/fixtures/docs, provider keys, GitHub tokens, everything else.)
- **Consequence:** a real AWS key inside `docs/`, `tests/` or a `.md` file only warns, unless TruffleHog confirms that it is live. Move rule 7 below rule 8 if that is not wanted.

## 5. We mask values ourselves, in memory
- **Chose:** Gitleaks reports raw values into a private temporary folder; we read them into memory, delete the folder, and **mask** them before anything is shown.
- **Why:** the policy must see the raw value to recognize placeholders such as `changeme`.
- **Rejected:** Gitleaks' own redaction (it would hide values from the policy too); keeping reports on disk. A possible improvement: read the report from Gitleaks' normal output, so it never touches the disk.

## 6. Masking shape
- **Chose:** values of 16+ characters show their first 4 and last 4 characters around `****`; shorter values become `****`.
- **Why:** enough to recognize a key, never enough to use it. The number of stars never changes, so the length stays hidden.

## 7. Fingerprints use a private key
- **Chose:** HMAC-SHA256, keyed by `SECUREGATE_HMAC_KEY` (at least 32 characters) or a random key stored in `.securegate/local.key`.
- **Why:** a plain hash of a short password can be cracked by hashing guesses. Without the key, a **fingerprint** reveals nothing.
- **Consequence:** the finding id is the start of the fingerprint, so the same secret in two places has the same id. The id names the secret, not the place.

## 8. Exit codes 0 / 1 / 2, and Gitleaks runs with `--exit-code 99`
- **Why:** Gitleaks normally uses 1 both for "found leaks" and for "crashed". A different number for leaks lets us tell them apart.

## 9. Fail closed
- **Chose:** any problem ends with exit code 2, never 0.
- **Found during the build:** asked to scan a folder that is not a Git repository, Gitleaks logs an error but exits 0 with an empty report. SecureGate now treats any error output from Gitleaks as a failure.

## 10. Nothing can silence a finding outside the policy
- **Chose:** `gitleaks:allow` comments in code are ignored, and a `.gitleaksignore` file in the scanned folder stops the scan with exit code 2.
- **Why:** otherwise a developer could hide a leak without the policy ever seeing it.
- **Rejected:** a warning only.

## 11. Gitleaks is only run from the PATH folders
- **Why:** on Windows, a program in the current folder would run first, and a scanned repository could contain a fake `gitleaks.exe`.

## 12. The ACME Pay rule has no randomness filter
- **Why:** placeholders like `acme_live_xxxx...` should reach the policy, which decides to ignore them. One place decides.

## 13. Only third-party folders may be skipped
- **Chose:** `.gitleaks.toml` skips Python virtual environments (installed packages). Our own code is never skipped.
- **Why:** if the scanner flags our code, we fix the code. A test scans our own files on every run.

## 14. No key-shaped text in our files
- **Chose:** fake secrets are built at runtime from a seed and short pieces; markers like PEM headers too.
- **Rejected:** sample keys stored in test files.

## 15. The demo repo lives outside SecureGate
- **Chose:** `../securegate-demo`, and never inside any Git repository. `--force` only empties a folder the generator made before; it leaves a `.securegate-demo` marker file there.
- **Rejected:** letting `--force` empty any folder.

## 16. Same seed, same demo repo
- **Chose:** a seed for every random choice, a fixed author (Riya Demo) and dates, and Git run without your personal Git settings.
- **Why:** results can be compared over time; the same seed gives the same commit IDs.

## 17. The answer sheet holds no values
- **Chose:** `ground_truth.csv` lists file, line, commit, kind and expected decision, never the value itself.

## 18. The scorecard is reported, not enforced
- **Why:** tests must not push the rules into looking good. First results (seed 42, repo mode): 15 hits, 2 **misses** (a database password inside a web address, a password with symbols), 1 wrong decision (the AWS secret key only warns: Gitleaks catches it with a generic rule), 2 **false alarms** (a client ID and a commit hash used as a cache key).

## 19. A simple confidence score, for now
- **Chose:** 0.9 for known key formats; for generic matches, entropy ÷ 6, at most 0.8.
- **Why:** a placeholder until a learned model replaces it. Confidence never decides anything; only the policy does.

## 20. findings.json has a summary at the top
- **Chose:** status, exit code, Gitleaks version and counts, then the findings. After an error there is no findings list at all.
- **Why:** a failed scan can never be mistaken for a clean one.

## 21. Tooling
- **Chose:** Python 3.12 (installed next to 3.14), GNU make from winget, setuptools, pytest and ruff; LF line endings in every file.
- **Why:** these match the plan; LF avoids Windows line-ending noise in Git.

## 22. Small helper modules added during the build
- `demo/app.py`: the fake app's files and commit story. `programs.py`: finds `git` and `gitleaks` safely. `validate.py`: shared checks for `policy.yaml` and `catalog.yaml`.
- **Why:** one job per module, and no copied code.

## 23. The dashboard is local and read-only
- **Chose:** a small Flask app that only reads one `findings.json`, answers only on 127.0.0.1 (this computer), and keeps debug off unless `--debug` is given.
- **Why:** findings are sensitive even when masked, so nobody else on the network should reach them, and a report viewer has no reason to change anything.
- **Rejected:** a shared web server, logins and editing (out of scope for now).

## 24. No JavaScript, and it works offline
- **Chose:** plain HTML and CSS. The Content-Security-Policy header forbids scripts, and every file comes from SecureGate itself.
- **Why:** nothing to download, nothing to break, and nothing for a malicious report to run. It works on a laptop with no internet.
- **Rejected:** JavaScript frameworks and chart libraries.

## 25. Severity bars are HTML meters
- **Chose:** one `<meter>` element per severity.
- **Why:** screen readers read them as values, and they need no inline styles, which the strict security policy would block.

## 26. The dashboard checks the masking again
- **Chose:** every `masked_value` must have the masked shape (`****`, or 4 characters + `****` + 4). A report that breaks this is refused, not shown.
- **Why:** a report edited by hand, or written by a future bug, must never put a whole secret on screen.

## 27. No report means a helpful page
- **Chose:** a missing, broken or failed report shows a page (HTTP 503) with the exact command that creates one. The report is read again for every page.
- **Why:** the first thing a new user sees tells them what to do next, and a new scan appears after a reload.

## 28. One detail page per secret
- **Chose:** `/findings/<id>` lists every place where that secret was found.
- **Why:** the id names the secret, not the place (see entry 7), and the fix (revoke and replace) is the same for all its places.

## 29. Design tokens with Fluent 2 names
- **Chose:** every colour, font size, spacing value and radius is a CSS variable in `tokens.css`, named like Fluent 2 tokens. Tests fail if `app.css` uses a raw value, or if text drops below WCAG AA contrast. Screens 1600 pixels and wider (projectors) get larger text and a wider page.
- **Why:** the designers can drop in their Figma tokens by changing values only, without breaking accessibility.

## 30. The sample report doubles the demo
- **Chose:** `make sample-report` scans a demo repo holding the DemoPay app twice (once under `billing/`), which gives about 20 real findings.
- **Why:** the usual demo scan has only 11 findings, and the designers need real data rather than invented rows.

## 31. Two gates, and only one of them is the control
- **Chose:** a laptop gate (a pre-commit hook on staged changes) and a merge gate (the `secret-gate` check on every pull request). Only the merge gate is required.
- **Why:** the laptop gate gives the fastest feedback but runs only where it is installed and can be skipped with `--no-verify`. The merge gate runs for every pull request on GitHub.
- **Rejected:** relying on the laptop gate alone.

## 32. The laptop gate brings its own Python environment
- **Chose:** a pre-commit hook with `language: python` and a small launcher, `tools/precommit_hook.py`, that runs this checkout's SecureGate.
- **Why:** a plain `securegate` command would only work with `.venv` activated, and on Windows a bare `python` is a different Python without SecureGate. After `make hooks` the hook works offline.

## 33. The merge gate scans every commit of a pull request
- **Chose:** a range scan from the pull request's base to its head, with no path filters on the trigger.
- **Why:** a secret deleted in a later commit is still in the history. A required check with path filters would never run for some pull requests and leave them stuck.

## 34. The base branch judges each pull request
- **Chose:** the workflow installs SecureGate, and takes `policy.yaml`, `.gitleaks.toml`, `.trufflehog.yaml` and `rules/`, from the pull request's base commit.
- **Why:** otherwise a pull request could loosen the policy or change the scanner and pass its own check. Changes to the gate count once merged.
- **Known limit:** a pull request can still edit the workflow file, because GitHub runs the pull request's copy. `merge-gate.md` recommends requiring an approval.
- **Consequence:** a change to the gate ships in two pull requests, code first and then the workflow that uses it; Layer 2 did exactly that.
- **Rejected:** `pip install -e .` of the pull request itself, as first specified.

## 35. Pinned actions and checked downloads
- **Chose:** `actions/checkout`, `actions/setup-python` and `actions/upload-artifact` (v7) and `github/codeql-action/upload-sarif` (v4), each at its latest major version (looked up on 2026-10-05), pinned to full commit SHAs with the version in a comment. Gitleaks and TruffleHog come from their official releases, and both the checksums file (its SHA-256 is pinned in the workflow) and the archive are verified before use. Semgrep and Bandit are installed with pip at pinned versions. Every version sits in one `env:` block at the top of the workflow.
- **Why:** a tag can be moved to other code; a commit SHA cannot. The pinned checksum also protects against a release file being replaced later.

## 36. The summary is a SecureGate output
- **Chose:** the scan writes the Markdown for GitHub's job summary (`--summary`, the same report as the pull request comment; `securegate summary` prints it for any `findings.json`), and a step that always runs and never changes the result adds it to the job's page.
- **Why:** it reuses the dashboard's report checks, so only masked values can reach GitHub's page, and it is tested like the rest of SecureGate.

## 37. Demo tokens use our invented ACME format
- **Chose:** `securegate demo-token` prints a new random `acme_live_` token each time, and the demo pull request uses only such tokens.
- **Why:** the repository is public. ACME Pay does not exist, so the token unlocks nothing, and GitHub's push protection does not know the format, so the token reaches the pull request and the gate can be shown for real.
- **Rejected:** fake tokens in real formats (Stripe, AWS, GitHub): push protection may stop them, and they look too much like real leaks.

## 38. The docs are Markdown, with PDF copies
- **Chose:** the pages in `docs/` stay Markdown, and `make docs-pdf` prints each one to `docs/pdf/` with headless Edge, styled with the dashboard's design tokens. A manifest records which version of each page its PDF came from; only changed pages are rebuilt, and a test fails when a PDF is out of date.
- **Why:** GitHub shows Markdown, pull requests can review it, and the gates scan it for secrets. Gitleaks skips PDF files, so PDF-only docs would never be checked.
- **Links between pages** appear in the PDFs as text, such as "Testing (testing.pdf)": the browser would otherwise write this computer's file paths into them.
- **Diagrams** are drawn by Mermaid 12.0.0, loaded from jsDelivr and checked against a pinned hash, so only that step needs the internet.
- **Rejected:** replacing the Markdown with PDFs; reportlab, which would mean laying out every page by hand.

## 39. The dashboard never shares its port
- **Chose:** SecureGate opens the dashboard's port itself, the way Python's `socket.create_server` does, and hands it to Flask's web server. A busy port stops the dashboard with exit code 2 and says what to do.
- **Why:** Flask's web server (Werkzeug) opens ports with a setting, `SO_REUSEADDR`, that on Windows lets a second server join a port another one is already using. Two dashboards then shared port 5000 without an error, and which one answered was left to chance. Where the port was really refused, Werkzeug ended the program with exit code 1, SecureGate's code for "blocked".
- **Rejected:** picking a free port automatically: the address would change from run to run, while the docs and the menu promise `127.0.0.1:5000`.

## 40. A double-click launcher for Windows
- **Chose:** `Start SecureGate.cmd` runs `.venv`'s Python directly, asks before setting anything up, checks the setup with `securegate version`, then opens the menu (entry 41).
- **Why:** `make` should not be needed just to see SecureGate work. A broken setup gets its own hint: delete `.venv`, then double-click again.
- **Rejected:** a PowerShell script: double-clicking one opens it in Notepad.

## 41. The double-click opens a menu
- **Chose:** `securegate menu` (also `make menu`): a numbered menu in the terminal, under a padlock and the name in big letters. Each choice runs the `securegate` commands a person would type, and shows each command before running it. Choice 1 builds the demo only when it is missing, scans it every time, and offers the dashboard only after a scan that ended with exit code 0 or 1. Enter closes the dashboard and brings the menu back.
- **Why:** SecureGate should open like an app for people who don't type commands, yet stay exactly the tool the gates use: the same commands, exit codes and masking. A rebuild would undo changes made to the demo for a presentation; a fresh scan follows the current `policy.yaml`; after a failed scan, the dashboard would only show the failure. Enter rather than Ctrl+C, because after Ctrl+C, cmd.exe asks "Terminate batch job (Y/N)?".
- **Colour** only in a real terminal, and never when `NO_COLOR` is set. ASCII letters when the terminal cannot show block characters. Q ends the menu with exit code 0; if its input ends, it stops with exit code 2, so it can never stand in for a gate.
- **Rejected:** a terminal-UI library such as Rich or Textual (a new dependency); answering with a single key press (Windows-only keyboard calls, and tests could not type the answers); the dashboard in a second window (one more window to close).

## 42. A dark dashboard, with downloads and a printable report
- **Chose:** a dark theme, a cool slate with one azure accent, and light colours when printed. The overview leads with the result in words (BLOCKED or PASS), then four tiles, the blocked findings with the most severe first, and the severity bars. The findings download as CSV, JSON or the Markdown summary, and `/report` puts the whole report on one page, to print or to save as a PDF.
- **Why:** dark reads well on a laptop and on a projector in a dim room, and light paper is cheaper to print and easier to read. Downloads are made from the same checked report the pages show, never by handing out `findings.json` as it is, so they can only hold masked values and the fields SecureGate knows. In the CSV, a cell that starts with `=`, `+`, `-` or `@` gets an apostrophe in front, because spreadsheet programs run such cells as formulas (the usual advice against CSV injection); a masked private key starts with dashes. The JSON download is a SecureGate report, so the dashboard and `securegate summary` can open it.
- **Severity dots** use status colours (critical red, high orange, medium amber, low and info grey), always next to the severity's name. The bars keep the one accent colour.
- **Rejected:** making PDFs on the server (a new dependency such as WeasyPrint, while the browser's Save as PDF already does it); buttons that print or download with JavaScript (the dashboard forbids scripts); a light/dark switch (it needs JavaScript, or a setting to remember).

## 43. Rules keep their number from the policy table
- **Chose:** each rule in `policy.yaml` carries its `number` from SecureGate's 14-rule policy table, and every report names the rule that decided as "rule 8: provider-keys" (the `matched_rule` field). Numbers go up from top to bottom; gaps are allowed: rules 2, 4, 5, 6, 11 and 12 were kept for later and never built (see [Roadmap](roadmap.md)). Error messages use the same numbers, such as `rule 10 ('hardcoded-passwords')`.
- **Why:** the table is how the team talks about the policy, so a report and a conversation should use the same name. The `reason` still starts with the rule's name, so older readers keep working.
- **Rejected:** numbering rules by their place in the file (adding one rule would renumber all the others).

## 44. The live-key rule looks at the key, not at the scanner's rule
- **Chose:** rule 8 matches the format of the value: `acme_live_`, `sk_live_` and `rk_live_`, AWS key ids (`AKIA` and its relatives), Bedrock keys, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) and private keys. Test-mode keys (`acme_test_`, `sk_test_`) only warn (rule 9).
- **Why:** four scanners name their rules differently, but a live key looks the same to all of them. Gitleaks' Stripe rule also matches test keys, which cannot move real money. Everything that Layer 1 blocked by rule name is still blocked.
- **Consequence:** a live key blocks as "high"; only a key that TruffleHog confirms is live is "critical" (rule 1).
- **Rejected:** matching scanner rule names (they differ per scanner and mix live and test keys).

## 45. TruffleHog is the second required scanner
- **Chose:** `--scanners all` adds TruffleHog to Gitleaks. Like Gitleaks it is required: if it is asked for and is missing, crashes or writes something unreadable, the scan ends with exit code 2. It runs with `--no-ignore-tag` (a `trufflehog:ignore` comment cannot hide a finding), `--fail-on-scan-errors` (a partial scan is an error) and `--no-update` (it never replaces itself with a version nobody pinned). Only its `Raw` field is read, and only to mask it; the other fields that can hold the secret, and the text of its logs, are never kept. It only scans Git history, so it is skipped in `dir` and `staged` modes, and the default stays Gitleaks alone (the laptop gate stays fast).
- **Why:** TruffleHog can ask the provider whether a key still works, which turns "looks like a key" into "is a live key" (rule 1).
- **Tests** run it only with `--no-verification`, so a fake key is never sent to a real provider. `.trufflehog.yaml` adds a detector for ACME Pay tokens without a check address, so TruffleHog contacts nobody about them.
- **Rejected:** `--fail` (its exit code 183 hides crashes among findings); reading TruffleHog's own `Redacted` text (it can show most of the key).

## 46. One finding per secret and line
- **Chose:** each scanner's finding is decided by the policy on its own; then the findings of the same key in the same file and commit become one, even if TruffleHog's line number is slightly off. A finding of Semgrep or Bandit is added to the secret found on its file and line, instead of becoming a finding of its own. The merged finding keeps the strongest decision (with that rule's reason and fix), the highest severity, the strongest live check, and every scanner that found it (`detectors`).
- **Why:** one leak should be one line in the report, with every piece of evidence about it, not four lines from four tools.
- **Rejected:** deciding once on a merged finding (a risky-handling warning on the same line as a placeholder would be lost).

## 47. Pinned scanners, installed and checked by `make scanners`
- **Chose:** the versions of TruffleHog, Semgrep and Bandit live in one place, the `env:` block at the top of the merge gate's workflow, and `CLAUDE.md` repeats them (a test checks that they match). `make scanners` installs Semgrep and Bandit into `.venv` with pip, and downloads TruffleHog from its GitHub release: the release's list of checksums must match a pinned SHA-256, the archive must match its line in that list, and only the program is taken out of the archive, into `.venv`'s scripts folder. SecureGate looks for programs on PATH and in that folder, never in the current folder.
- **Why:** the laptop and GitHub run the same versions, and a download is checked before it runs.
- **Rejected:** `curl | sh` install scripts (nothing is checked before it runs); winget (it has no TruffleHog package).

## 48. Semgrep and Bandit read a private copy of the code, and are optional
- **Chose:** `--scanners all` also runs Semgrep (Semgrep's p/secrets rules plus our own `rules/securegate-risky.yml`) and Bandit (its password checks B105, B106 and B107). They read code, not history: a private copy of the files the range changed, as they are at its end (in a repo scan, every tracked file at HEAD), taken from Git with `git archive`. Ignore files (`.semgrepignore`, `.gitignore`, `.bandit`) are left out of the copy and an empty `.semgrepignore` is written instead; Semgrep runs with `--disable-nosem` and Bandit with `--ignore-nosec`, so neither a file nor a comment in a pull request can hide code from them. If one of them fails or is missing, the scan goes on and the report records that it did not run. If p/secrets cannot be downloaded, Semgrep runs our own rules alone and the report says so.
- **Why:** they add evidence that Gitleaks and TruffleHog cannot give: passwords next to their names, and code that leaks a secret into a log or a URL. But they look at code, not at secrets in history, so a pull request should not be stopped just because one of them could not run.
- **Values:** only the rule, the file and the line are read from their output. Semgrep's `extra.lines` and `extra.message`, and Bandit's `code` and `issue_text`, quote the secret and are never kept: the value is cut out of our own copy (Semgrep) or out of Bandit's message, in memory, and masked at once. Our own Semgrep rules point at code, not at a secret, so their findings show `****` and nothing of the line.
- **Rejected:** scanning the working tree (it may not be the commit being judged); letting Semgrep use the repository's ignore files; `python -m semgrep` (deprecated by Semgrep).

## 49. One Markdown report for the pull request, and SARIF from our own findings
- **Chose:** `securegate scan --comment FILE --summary FILE --sarif FILE`. The comment and the job summary are the same report from one template: a one-line verdict (BLOCKED, PASSED WITH WARNINGS, PASSED, or ERROR when the scan did not finish), a table (decision, rule, file and line, masked value, the scanners that found it, the live check), a rotation checklist for every blocked key (ACME Pay, Stripe, AWS, GitHub, private keys, or a general one) ending with "Deleting the line is not enough: the key stays in Git history.", why each warning was not blocked, and the ignored findings folded away. The comment starts with a hidden marker, so the workflow can update its own comment instead of adding one per run. A scanner that did not run shows as a red CAUTION note. The SARIF file has one rule per policy rule, with its severity, and only the blocks and warnings.
- **Why:** everything a reviewer needs is in the pull request itself, in plain words. Building every output from `findings.json`, read back through the dashboard's check that every value is masked, means no output can hold more than that check let through, and every value is escaped so a file name cannot break the table or add HTML.
- **Consequences:** after an error, the comment and summary say ERROR and any old SARIF file is deleted, because uploading an empty one would tell GitHub that every earlier alert was fixed. Long reports stop after 50 rows (GitHub refuses comments over 65,536 characters); `findings.json` keeps everything.
- **Rejected:** uploading the scanners' own SARIF (it holds unmasked values and none of our decisions); a red text colour through GitHub's maths notation (it does not degrade gracefully where it is not rendered).

## 50. The workflow: four scanners, one comment, and the exit code decides last
- **Chose:** `secret-gate` runs on every pull request to main (no path filters), once per pull request at a time (a new push cancels the older run), with a 10-minute limit. Its token may read the code, write pull request comments and upload SARIF, nothing else. The scan step runs all four scanners on every commit of the pull request and saves SecureGate's exit code instead of failing at once; the summary, the SARIF upload (only after a finished scan), the `findings.json` artifact and the comment then always run and can never change the result; the last step passes or fails the check with the saved code, and with 2 when the scan never ran. The comment is found again by its hidden marker and updated, so a pull request gets one comment, not one per push. TruffleHog checks whether keys are live here (`--no-verification` is for tests only).
- **Why:** reviewers see everything in the pull request, and nothing that only reports can turn a red check green or a green one red.
- **Forks:** a pull request from a fork gets a read-only token, so it gets no comment and no SARIF upload; its check still runs and decides.
- **Rejected:** failing in the scan step (the summary and comment would be skipped exactly when they matter most); a new comment on every push; uploading SARIF after an error.

## 51. The menu runs the four-scanner scan, and shows the pull request comment
- **Chose:** two more choices in the menu (entry 41). **2** scans the demo project with all four scanners, exactly like `make scan-demo-all` (a test parses both commands and compares them), with live checks off, then offers to show the pull request comment in the window. **3** shows that comment again. Choices 2 to 6 became 4 to 8. For a Git project of your own, choice 4 offers all four scanners when TruffleHog is installed, and asks before TruffleHog sends any key it finds to its provider (the default is no). `securegate version`, and so choice 8, also prints the versions of TruffleHog, Semgrep and Bandit.
- **In the terminal,** the comment loses its hidden marker and the HTML around the folded list; headings are bold and a scanner that did not run is red; a table is shown in columns when it fits the window, and row by row when it does not; text wraps without splitting a path or a masked value; control characters are removed.
- **Why:** the whole demo, the merge gate's comment included, can be presented from one window, without typing commands and without the internet. The comment is made from the checked report, like every other output, so it holds masked values only. Sending found keys to a provider is the person's decision, not the menu's.
- **Rejected:** four scanners on choice 1 (Gitleaks alone first shows what a single scanner misses); a pager for the comment (the terminal's own scrollback does the job, with nothing new to learn); fetching the real comment from GitHub (needs the internet and a sign-in); Rich for the terminal (a new dependency).

## 52. Demo pull requests are made by SecureGate, in a temporary worktree
- **Chose:** `securegate demo-pr <clean|leak|deleted-later|decoys|risky>` (`make demo-clean`, `demo-leak`, `demo-deleted`, `demo-decoys`, `demo-risky`) opens a real pull request on GitHub for each scene. It refuses to start when the working tree has changes, `gh` is not signed in, or `origin` is not on GitHub. It fetches main, makes a temporary git worktree from `origin/main` on a new branch `demo/<scene>-<UTC time>`, writes the scene's files from templates with fake values made at random, commits with `--no-verify` (the laptop gate would stop the leak), pushes exactly that branch, and opens the pull request with `gh pr create`. The worktree and its folder are removed afterwards, whatever happened. `securegate demo-cleanup` closes every open pull request whose branch starts with `demo/` (`--delete-branch`), skipping pull requests from forks, then deletes the remaining `demo/` branches on origin and here, except one that is checked out.
- **Why:** the manual demo took seven steps, and a mistake in one of them (a wrong branch, a forgotten clean-up, a key left in the working tree) is exactly what a demo cannot afford. A worktree leaves the person's own checkout, branch and files untouched; a fresh branch from origin/main means each scene shows only its own commits. Every branch name is checked against `demo/` before `git` or `gh` touches it, so nothing can push to, commit to or delete main.
- **Values:** the fake ACME Pay tokens and the password are made at random for each pull request and written only into its files, never printed: the command shows the address, the branch, what the scene contains and what the gate should say. `reports/demo-pr.json` keeps the number, address, branch and scene of the newest one (no values), for `ci-report --pr` and the menu.
- **Rejected:** committing on the person's own branch (it would change their checkout); keeping the scenes' files in the repository (they would hold key-shaped text, which rule 2 forbids, and the self-scan would flag them); pushing with `--force` (never needed: every branch is new).

## 53. `doctor` and `ci-report`
- **Chose:** `securegate doctor` prints PASS, FAIL or SKIP for each thing the demo needs: the four scanners at the workflow's pinned versions, `policy.yaml`, the workflow with its `secret-gate` job (here and on GitHub's main), `gh` signed in, `origin` on GitHub, and a ruleset on main that requires the `secret-gate` check. It only reads, and ends with exit code 1 when something failed. `securegate ci-report` downloads `findings.json` from a `secret-gate` run (the newest; `--run ID`; or `--pr N`, the run for the pull request's newest commit), checks it with the dashboard's loader, saves it as `findings-ci.json` and opens the dashboard. `--wait` waits for a run that has not finished (up to 15 minutes), and with `--pr` it says what GitHub allows: "Merging: locked" when the ruleset holds the pull request.
- **Why:** a demo should fail before the judges arrive, not in front of them, and the check that matters most (does a red check lock the merge button?) is a GitHub setting that cannot be seen from the laptop. The gate's report is already masked and uploaded by the workflow, so the dashboard can show it on the laptop with nothing new to trust: it is checked like any other report.
- **Rejected:** setting the ruleset from `doctor` (it changes GitHub; `docs/merge-gate.md` gives the one command, for the owner to run); polling GitHub's API with `urllib` (`gh` already holds the sign-in).

## 54. The merge gate in the menu
- **Chose:** choice 9 opens a second screen, "The merge gate on GitHub": 1 to 5 open the five demo pull requests (each shows what the gate should say), 6 shows the result of the last one, 7 the report of the newest run, 8 closes every demo pull request (it asks first, and the default is no), and 9 runs `doctor`; B goes back. After a demo pull request opens, the menu offers to open it in the browser, then to wait for its check (`securegate ci-report --pr N --wait`), then to open its report in the dashboard. Like every choice, each step runs a `securegate` command and shows it first.
- **Why:** the GitHub part of the demo can be shown from the same window as the rest, without typing commands, and the judges still see the real commands.
- **Safety:** the menu reads the newest pull request from `reports/demo-pr.json`, and only opens its address in the browser when it is a GitHub pull request address whose number matches; anything else is ignored.
- **Rejected:** buttons in the dashboard (it is read-only, with no JavaScript, by design: entry 42); a single key press per choice (entry 41).

## 55. CODEOWNERS, without a required review yet
- **Chose:** `.github/CODEOWNERS` names the owner of `.github/`, `policy.yaml`, `.gitleaks.toml`, `.trufflehog.yaml` and `rules/`, the files that decide what the merge gate does. The ruleset does not require their review.
- **Why:** a pull request can edit the workflow that judges it (GitHub runs the pull request's copy), so changes to these files need a person's eyes. But on a repository with one maintainer, a required code-owner review would block every such pull request, because nobody can approve their own. [Limitations](limitations.md) says so, and how to switch it on.

## 56. Three AI agents that advise, on Azure AI Foundry
- **Chose:** three agents (`securegate agents`): triage, fix and incident. They advise only: their output is kept in the report's `advice` section and shown as advice, and never changes a decision or an exit code. Each one is a bounded loop: the model may call five read-only tools (the findings list, the code around a finding, a policy rule, SecureGate's checklist for a kind of key, and git facts), at most 6 times, then must answer in a strict JSON format. The model is a deployment in Azure AI Foundry, `gpt-5.4-mini` by default, called with Python's own HTTPS client.
- **Why:** reviewers get a second opinion on each finding, a ready line of code, and a response plan, while the gate's verdict stays where it was: in the readable policy. GitHub Models, the first choice, was retired on 2026-07-30; Azure AI Foundry is Microsoft's replacement, and the same Azure account was meant to host the live checks, which were never built. `gpt-5.4-mini` is only the default deployment name: any chat model deployed in Azure AI Foundry works, named by its deployment, and the agents were verified on a `gpt-5-mini` deployment.
- **Nothing secret is sent:** each finding's value is located by its fingerprint and replaced by `<SECRET>`; key shapes, random-looking tokens, passwords in web addresses and string literals on the finding's line are removed too; a value that cannot be located means no code is sent at all. Answers are untrusted: checked against the format, cleaned of markup, links, mentions and anything secret-shaped, and checked again whenever a report is read.
- **Rejected:** letting the agents decide (the policy must stay readable and testable); an SDK such as `openai` (a new dependency for one HTTPS call); tools that write or run commands (prompt injection could use them); GitHub Models (retired).

## 57. The advice lives in the report
- **Chose:** `securegate agents` writes its advice into the report it was asked about, and reads it back through the dashboard's checks; advice that fails them is replaced by a "failed" status. The pull request comment, the job summary, the dashboard (an AI advice page, a panel on each finding, a line on the overview), the JSON download and the menu (choice A, and an offer after each scan once the agents are set up) all read it from there.
- **Why:** one file carries everything, so `make ci-report` brings the merge gate's advice to the dashboard with nothing new to trust.
- **Rejected:** a separate advice file (two files to keep together, and a second loader to check).

## 58. The fix agent chooses names; SecureGate makes the edit
- **Chose:** `securegate agent-fix --pr N` (also 9, then F, in the menu) opens a pull request into the given pull request's branch, from this laptop, with the person's own gh login. It scans the pull request's commits here, asks the fix agent which environment variable each key should come from, and then makes each edit itself: only the quoted literal that holds the key is replaced, by `os.environ["NAME"]` (Python) or `process.env.NAME` (JavaScript), and `import os` is added when a Python file lacks it. The fix branch is `demo/fix-...` for a demo pull request, so `demo-cleanup` removes it too.
- **Why:** a model's whole rewritten line could change what the line does, and it only ever saw `<STRING>` in place of the line's other strings. A literal swapped by SecureGate changes exactly one thing, and the edit is checked again against the real file: the key must be gone from the line.
- **Not in the merge gate:** fixing would need a token that can push. The gate keeps its read-only token; the comment shows the suggestion instead.
- **Rejected:** applying the model's line as it is; a fix for a key that is only in an older commit (only revoking it helps); fixing a key inside a longer string, such as a web address with a password (left for a person).

## 59. The merge gate asks the agents, after it has decided
- **Chose:** a step "Ask the AI agents (advice only)" right after the scan: only after a finished scan (exit code 0 or 1), with `continue-on-error` and a 3-minute limit, before the summary, the comment and the `findings.json` artifact are written, so all three carry the advice. The key comes from the repository secret `SECUREGATE_AI_KEY`, the endpoint and deployment from repository variables, and the repository's visibility is passed on for the incident plan. Like every step, it runs SecureGate from the base branch: the pull request's code is only data.
- **Why:** reviewers see the advice where they already look, and the check stays exactly the policy's verdict.
- **Forks** get no secrets from GitHub, so their comment says the agents were not asked; their check is unchanged.
- **Rejected:** running the agents before the policy (they would look like part of the decision); failing the check when Azure is down.

## 60. The project closes as v1.0.0, in the repository Nexora
- **Chose:** after Microsoft Innovate 2026, the project was finished rather than left half-done: version 1.0.0, the MIT license, and every page checked against the code. The GitHub repository SecureGate was renamed to Nexora, the team's name; the product keeps its name. The old Nexora repository, which only held copies of early branches, was renamed to Nexora-backup first.
- **Why:** a rename keeps the history, the pull requests, the gate's runs and the Security tab's alerts in one place, and GitHub sends the old address to the new one.
- **Rejected:** pushing into a second repository (it would split the code from its pull requests and checks); rewriting history; deleting either repository.

## 61. Other repositories use the gate as a GitHub Action
- **Chose:** `action.yml`, a composite action that runs the steps of the workflow (entry 50): `uses: Bhavik-Kadian/Nexora@v1.0.0`. SecureGate comes from the action, at the tag the caller chose. The policy comes from the caller's base branch, as in entry 34: their `policy.yaml`, or SecureGate's own when they have none. The scanners' own rules come from the action. The AI agents are only asked when the caller passes a key. It fails closed on any event but a pull request, without the full history, and when a policy file it was told to use is not merged yet.
- **Why:** any repository gets the same gate, with the same guarantees, from one short workflow file.
- **Not used by SecureGate itself:** its own gate keeps installing SecureGate from the base branch (entry 34). Running the action from the pull request's own copy (`uses: ./`) would let a pull request change the gate that judges it. Tests keep the action's versions, checksums, action pins and scripts equal to the workflow's.
- **Rejected:** copying the whole workflow into each repository (every copy would need the same fixes by hand); a Docker action (slower, and harder to pin).

## 62. Exact versions, and a fixed runner
- **Chose:** every package at the version it was tested with: the direct dependencies and the build backend in `pyproject.toml`, everything they pull in in `constraints.txt` (used by `make setup` and the action), and the laptop gate's two packages. The merge gate runs on `ubuntu-24.04` instead of `ubuntu-latest`.
- **Why:** the project is no longer maintained, so nobody would notice when a new release breaks a fresh clone. A new ruff release, for one, adds lint rules, and `make check` would fail. Pinned, `make setup && make check` keeps working as long as those versions can be downloaded.
- **Rejected:** version ranges such as `>=6.0`; a lock-file tool (a new dependency).

## 63. Working notes stay, in docs/history
- **Chose:** the build plan, the approved plan of each stage (the live-checks plan that was never built among them) and the judging-day script moved to `docs/history/`, unchanged but for a note on top. `docs/roadmap.md` lists what was never built.
- **Why:** they explain why the code is the way it is. Deleting them would lose that, and the next person would have to guess.
