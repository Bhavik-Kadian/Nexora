# Glossary

**CI (continuous integration)**: a service that runs checks automatically every time someone proposes a change to a project. Example: GitHub shows a red cross on a pull request when a check fails. A later SecureGate version will run there as a merge gate.

**Commit**: a saved snapshot of a project in Git, with a message, an author and a date.

**Decoy**: something that looks like a secret but is not. Example: a 40-character commit hash, or a placeholder.

**Entropy**: a score for how random a piece of text looks, in bits per character. Example: `aaaa` scores 0; a random key scores about 4 to 6. Scanners use it to tell keys from ordinary words.

**Exit code**: the number a program gives back when it finishes, so other tools can react. SecureGate: 0 = pass, 1 = something is blocked, 2 = SecureGate could not do its job.

**False negative (miss)**: a real secret that the tool did not report. Example: a database password hidden inside a web address.

**False positive (false alarm)**: something reported as a secret that is not one. Example: a random-looking cache key.

**Fingerprint**: a code made from a secret that recognizes the same secret again, without storing it. SecureGate mixes in a private key (a method called HMAC), so nobody can work back from the fingerprint to the secret, or test guesses against it. Example: `dcc7b5bb...` (64 characters).

**Git history**: every commit ever made in a repository. Deleting a line in a new commit does not remove it from the older ones.

**Gitleaks**: a free, open-source scanner that finds key-shaped text in files and in Git history. SecureGate uses it to find candidates, then decides itself.

**Hardcoded**: written directly into the code, instead of being loaded from a safe place when the program runs. Example: a Stripe key typed into a Python file.

**Masking**: hiding most of a value before showing it. SecureGate keeps the first 4 and last 4 characters of values with 16 or more characters, like `sk_l****562d`. Shorter values become `****`.

**Placeholder**: a made-up stand-in value. Example: `YOUR_API_KEY_HERE` or `changeme`.

**Policy**: the rules in `policy.yaml` that decide block, warn or ignore for each finding.

**Pre-commit**: the moment just before a change is saved as a commit. A pre-commit check can stop a secret before it ever enters the history. Example: `securegate scan . --mode staged` checks exactly the changes about to be committed.

**Repository (repo)**: a project folder together with its Git history.

**Rotation**: replacing a leaked secret with a new one and cancelling the old one, so the leaked copy stops working. It is the only real fix for a leak.

**Secret**: a password, key or token that gives access to something: money, data, servers or code. Example: a Stripe live key lets you take card payments.
