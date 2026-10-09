# SecureGate

SecureGate checks a code project for **secrets**: passwords, keys and tokens that give access to money, data or servers.
It looks through every saved version of the project, not only the latest one.
One readable file, `policy.yaml`, decides what happens to each thing it finds: **block**, **warn** or **ignore**.
It never shows a whole secret: a found key appears as `sk_l****562d`.
It checks each commit on your laptop and each pull request on GitHub, a read-only dashboard shows the results in your browser, and optional AI agents explain them.

**Completed:** built by Team Nexora for Microsoft Innovate 2026 (Problem Statement 24). Version 1.0.0 is the last release, and the project is not actively maintained. Everything on these pages works as described; what was never built is listed in the [Roadmap](roadmap.md).

**See it work:** on Windows, double-click `Start SecureGate.cmd` in the SecureGate folder. SecureGate opens with its menu. Type 1 and press Enter to scan a demo project full of fake secrets, then press Enter again to see the results in your browser. Type 9 to see the gate on GitHub: SecureGate opens a real pull request with a fake key, and shows how the check stops it. Type A for the AI agents: triage, fixes and an incident plan for the findings. The first time, install the tools in step 1 of [Getting started](getting-started.md).

## Start here

| Page | Read it when you want to... |
|---|---|
| [Getting started](getting-started.md) | install SecureGate, run your first scan, and look up every command |
| [Demo day](demo-day.md) | show SecureGate to anyone in 10 minutes, from the menu, step by step |
| [Protect any repository](install.md) | give another GitHub repository the same two gates: the GitHub Action and the pre-commit hook |

## Use it

| Page | Read it when you want to... |
|---|---|
| [How it works](how-it-works.md) | follow one leaked key from discovery to report |
| [The two gates](merge-gate.md) | stop secrets before a commit (laptop) and before a merge (GitHub), and turn the GitHub check on |
| [Demo: the merge gate](demo-script.md) | show the GitHub check at work in five scenes, from the menu or with one command each |
| [Dashboard](ui.md) | see a report in your browser, download or print it, or change the dashboard's colours |
| [The AI agents](agents.md) | get AI advice on the findings: triage, a fixed line of code and an incident plan |
| [Testing](testing.md) | plant a new secret in the demo repo and read the scorecard |

## Understand it

| Page | Read it when you want to... |
|---|---|
| [How it's built](how-its-built.md) | find your way around the files, or change a behavior |
| [Decisions](decisions.md) | know why something is the way it is |
| [Limitations](limitations.md) | know what SecureGate does not do, and what to do about it |
| [Glossary](glossary.md) | look up a word |

## The project

| Page | Read it when you want to... |
|---|---|
| [Project closure](project-closure.md) | see what was built, what works today, the final results, and how to bring each part back |
| [Roadmap](roadmap.md) | see what was planned but never built |
| [History](history/README.md) | read the working notes and plans from the build, kept as they were written |
| [Changelog](../CHANGELOG.md) | see what changed, stage by stage |
| [Security](../SECURITY.md) | report a problem, and know why every key here is fake |
| [Close-out checklist](../CLOSEOUT-CHECKLIST.md) | see what is left for the repository's owner to do |
| [License](../LICENSE) | reuse the code: MIT, Copyright (c) 2026 Team Nexora |
| [The front page](../README.md) | see the project at a glance |

Every page in `docs/` is also a PDF, for printing or sharing: see the `docs/pdf/` folder. The pages above are the originals. After changing one, run `make docs-pdf` to update its PDF.
