"""Masking and fingerprinting: the only way a raw secret becomes something we may keep.

protect(raw, key) returns a MaskedSecret that holds:
  * a masked text: values of 16+ characters keep only their first 4 and last 4 characters,
    shorter values become "****";
  * a fingerprint: HMAC-SHA256 of the raw value, so the same secret can be recognised again
    without storing it.
Nothing else in SecureGate may keep a raw value.
"""

import hashlib
import hmac
import os
import secrets
from collections.abc import Mapping
from dataclasses import InitVar, dataclass
from pathlib import Path

from securegate.errors import ConfigError

HIDDEN = "****"
MIN_SHOWN_LENGTH = 16  # shorter values are hidden completely
EDGE = 4  # characters shown at each end of longer values
ID_LENGTH = 12  # a finding id is the start of its fingerprint

KEY_ENV_VAR = "SECUREGATE_HMAC_KEY"
KEY_MIN_LENGTH = 32
STATE_DIR_NAME = ".securegate"
LOCAL_KEY_FILE = "local.key"

_MINT = object()  # only protect() holds this, so only protect() can create a MaskedSecret


@dataclass(frozen=True, slots=True)
class MaskedSecret:
    """A secret after masking: safe to print, store and share."""

    masked: str
    fingerprint: str
    mint: InitVar[object] = None

    def __post_init__(self, mint: object) -> None:
        if mint is not _MINT:
            raise TypeError("a MaskedSecret can only be created by securegate.mask.protect()")

    @property
    def id(self) -> str:
        """Short id: the first 12 hex characters of the fingerprint."""
        return self.fingerprint[:ID_LENGTH]


def protect(raw: str, key: bytes, *, hide_all: bool = False) -> MaskedSecret:
    """Mask and fingerprint a raw value. This is the only way to create a MaskedSecret.

    `hide_all` shows nothing of the value: for a line of code that handles a secret (a
    Semgrep risky-handling finding), whose edges would not mean anything to a reader.
    """
    masked = HIDDEN if hide_all else mask_value(raw)
    return MaskedSecret(masked, fingerprint(raw, key), _MINT)


def mask_value(raw: str) -> str:
    """Hide a value, keeping at most its first 4 and last 4 characters."""
    if len(raw) < MIN_SHOWN_LENGTH:
        return HIDDEN
    return _printable(raw[:EDGE]) + HIDDEN + _printable(raw[-EDGE:])


def fingerprint(raw: str, key: bytes) -> str:
    """HMAC-SHA256 of the value as 64 hex characters. Same value and key: same fingerprint."""
    return hmac.new(key, raw.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


def _printable(text: str) -> str:
    """Keep plain printable ASCII only; anything else (newline, tab, accents) shows as '?'."""
    return "".join(ch if " " <= ch <= "~" else "?" for ch in text)


def default_state_dir() -> Path:
    """Where SecureGate keeps local state: the .securegate folder in the current folder."""
    return Path.cwd() / STATE_DIR_NAME


def load_hmac_key(env: Mapping[str, str], state_dir: Path) -> bytes:
    """Return the fingerprint key.

    1. SECUREGATE_HMAC_KEY from the environment, when set (at least 32 characters).
    2. Otherwise the key in <state_dir>/local.key, created once with random content.
    """
    from_env = env.get(KEY_ENV_VAR)
    if from_env is not None:
        key = from_env.strip()
        if len(key) < KEY_MIN_LENGTH:
            raise ConfigError(
                f"{KEY_ENV_VAR} is too short: it needs at least {KEY_MIN_LENGTH} characters. "
                'Make one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        return key.encode("utf-8")
    return _load_or_create_key_file(state_dir)


def _load_or_create_key_file(state_dir: Path) -> bytes:
    key_path = state_dir / LOCAL_KEY_FILE
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        _ignore_in_git(state_dir)
        if not key_path.exists():
            _create_key_file(key_path)
        key = key_path.read_text(encoding="utf-8").strip()
    except OSError as err:
        raise ConfigError(f"cannot read or create the fingerprint key file: {err}") from None
    if len(key) < KEY_MIN_LENGTH:
        raise ConfigError(
            f"the fingerprint key file {key_path} is damaged. Delete it and SecureGate will make "
            "a new one (fingerprints from earlier scans will then stop matching)."
        )
    return key.encode("utf-8")


def _create_key_file(key_path: Path) -> None:
    """Create the key file with owner-only access (mode 600 on macOS and Linux)."""
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return  # another SecureGate run created it a moment ago
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(secrets.token_hex(32) + "\n")


def _ignore_in_git(state_dir: Path) -> None:
    """Put a .gitignore containing '*' in the folder, so Git ignores it in any repository."""
    ignore_file = state_dir / ".gitignore"
    if not ignore_file.exists():
        ignore_file.write_text(
            "# Created by SecureGate. Never commit this folder.\n*\n", encoding="utf-8"
        )
