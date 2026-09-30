# SecureGate

SecureGate checks a code project for **secrets**: passwords, keys and tokens that give access to money, data or servers.
It looks through every saved version of the project, not only the latest one.
One readable file, `policy.yaml`, decides what happens to each thing it finds: **block**, **warn** or **ignore**.
It never shows a whole secret: a found key appears as `sk_l****562d`.
A read-only dashboard shows the results in your browser; a merge gate and AI helpers come later.

## Pages

| Page | Read it when you want to... |
|---|---|
| [Getting started](getting-started.md) | install SecureGate and run your first scan |
| [How it works](how-it-works.md) | follow one leaked key from discovery to report |
| [Dashboard](ui.md) | see a report in your browser, or change the dashboard's colours |
| [How it's built](how-its-built.md) | find your way around the files, or change a behavior |
| [Testing](testing.md) | plant a new secret in the demo repo and read the scorecard |
| [Glossary](glossary.md) | look up a word |
| [Decisions](decisions.md) | know why something is the way it is |
