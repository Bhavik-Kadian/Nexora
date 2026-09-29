# Decisions

The choices behind SecureGate v0.1: what we chose, why, and what we rejected. Add an entry whenever you make a choice that someone might question later. Words in bold are explained in the [Glossary](glossary.md).

## 1. Gitleaks finds, SecureGate decides
- **Chose:** **Gitleaks** finds candidate secrets; our own `policy.yaml` decides what happens to them.
- **Why:** Gitleaks already knows many key formats and is widely used. What we add is the decision and the safe reporting.
- **Rejected:** writing our own detection rules for every provider; TruffleHog (out of scope for v0.1).

## 2. One readable policy, first match wins
- **Chose:** rules checked from top to bottom; the first rule that matches decides.
- **Why:** anyone can read the file and predict the result.
- **Rejected:** scores and weights (hard to predict); several policy files.

## 3. The last rule must match everything
- **Chose:** a policy without a final catch-all rule, or with unknown words in it, is refused (exit code 2).
- **Why:** every finding gets a decision, and a typo can never switch a rule off silently.
- **Rejected:** a hidden default decision.

## 4. Rule order as specified
- **Chose:** placeholders, then tests/fixtures/docs, then provider keys, then GitHub tokens, then everything else.
- **Consequence:** a real AWS key inside `docs/` or `tests/` only warns. Move the provider rules up if that is not wanted.

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
