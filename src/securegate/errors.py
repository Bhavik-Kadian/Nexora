"""Error types. Every SecureGateError stops SecureGate with exit code 2 (fail closed).

Error messages are shown to people, so they must never contain a secret value.
"""


class SecureGateError(Exception):
    """A problem that stops SecureGate. The CLI turns it into exit code 2."""


class ConfigError(SecureGateError):
    """Bad configuration: policy.yaml, catalog.yaml, the fingerprint key or a CLI option."""


class ScannerError(SecureGateError):
    """The scanner is missing, crashed, or wrote a report we cannot read."""


class DemoError(SecureGateError):
    """The demo generator refused to run, for example because the output folder is not empty."""
