# SecureGate

SecureGate checks a code project for **secrets**: passwords, keys and tokens that give access to money, data or servers.
It looks through every saved version of the project, not only the latest one.
One readable file, `policy.yaml`, decides what happens to each thing it finds: **block**, **warn** or **ignore**.
It never shows a whole secret: a found key appears as `sk_l****562d`.
It checks each commit on your laptop and each pull request on GitHub, and a read-only dashboard shows the results in your browser.

**See it work:** on Windows, double-click `Start SecureGate.cmd` in the SecureGate folder. SecureGate opens with its menu. Type 1 and press Enter to scan a demo project full of fake secrets, then press Enter again to see the results in your browser. The first time, install the tools in step 1 of [Getting started](getting-started.md).

## Pages

| Page | Read it when you want to... |
|---|---|
| [Getting started](getting-started.md) | install SecureGate and run your first scan |
| [How it works](how-it-works.md) | follow one leaked key from discovery to report |
| [Dashboard](ui.md) | see a report in your browser, or change the dashboard's colours |
| [The two gates](merge-gate.md) | stop secrets before a commit (laptop) and before a merge (GitHub), and turn the GitHub check on |
| [Demo: the merge gate](demo-merge-gate.md) | show the GitHub check stopping a fake key, step by step |
| [Presenting to judges](presenting-to-judges.md) | show SecureGate live: where it starts, where the data comes from, what to type and what to say |
| [How it's built](how-its-built.md) | find your way around the files, or change a behavior |
| [Testing](testing.md) | plant a new secret in the demo repo and read the scorecard |
| [Glossary](glossary.md) | look up a word |
| [Decisions](decisions.md) | know why something is the way it is |

Every page is also a PDF, for printing or sharing: see the `docs/pdf/` folder. The pages above are the originals. After changing one, run `make docs-pdf` to update its PDF.
