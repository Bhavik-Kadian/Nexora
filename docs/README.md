# SecureGate

SecureGate checks a code project for **secrets**: passwords, keys and tokens that give access to money, data or servers.
It looks through every saved version of the project, not only the latest one.
One readable file, `policy.yaml`, decides what happens to each thing it finds: **block**, **warn** or **ignore**.
It never shows a whole secret: a found key appears as `sk_l****562d`.
It checks each commit on your laptop and each pull request on GitHub, and a read-only dashboard shows the results in your browser, where you can download them or print them.

**See it work:** on Windows, double-click `Start SecureGate.cmd` in the SecureGate folder. SecureGate opens with its menu. Type 1 and press Enter to scan a demo project full of fake secrets, then press Enter again to see the results in your browser. Type 9 to see the gate on GitHub: SecureGate opens a real pull request with a fake key, and shows how the check stops it. Type A for the AI agents: triage, fixes and an incident plan for the findings. The first time, install the tools in step 1 of [Getting started](getting-started.md).

**Showing it to judges?** Start with [Demo day](demo-day.md): the whole demo on one page, from the menu.

## Pages

| Page | Read it when you want to... |
|---|---|
| [Demo day](demo-day.md) | show SecureGate to judges in 10 minutes, from the menu, step by step |
| [Getting started](getting-started.md) | install SecureGate and run your first scan |
| [How it works](how-it-works.md) | follow one leaked key from discovery to report |
| [Dashboard](ui.md) | see a report in your browser, download or print it, or change the dashboard's colours |
| [The two gates](merge-gate.md) | stop secrets before a commit (laptop) and before a merge (GitHub), and turn the GitHub check on |
| [Protect any repository](install.md) | give another GitHub repository the same two gates: the GitHub Action and the pre-commit hook |
| [Demo: the merge gate](demo-script.md) | show the GitHub check at work in five scenes, from the menu or with one command each |
| [How it's built](how-its-built.md) | find your way around the files, or change a behavior |
| [Testing](testing.md) | plant a new secret in the demo repo and read the scorecard |
| [The AI agents](agents.md) | get AI advice on the findings: triage, a fixed line of code and an incident plan |
| [Limitations](limitations.md) | know what SecureGate does not do yet, and what to do about it |
| [Glossary](glossary.md) | look up a word |
| [Decisions](decisions.md) | know why something is the way it is |
| [Roadmap](roadmap.md) | see what was planned but never built |
| [History](history/README.md) | read the working notes and plans from the build, kept as they were written |

Every page is also a PDF, for printing or sharing: see the `docs/pdf/` folder. The pages above are the originals. After changing one, run `make docs-pdf` to update its PDF.
