"""SecureGate's AI agents: triage, fix and incident. They advise; policy.yaml still decides.

No agent ever sees a whole secret (redact.py removes every one before anything is sent), and
everything an agent answers is treated as untrusted text (sanitize.py, advice.py).
"""
