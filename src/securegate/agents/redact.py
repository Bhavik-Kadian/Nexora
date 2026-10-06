"""Taking every secret out of text before an AI agent sees it.

Two layers, so that one mistake is not enough to leak:
  1. Exact. Each finding's own value is located on its line by its fingerprint: the HMAC that
     made the report (mask.fingerprint, with the same key). For a long value, the candidates
     are the substrings that start and end with the four characters its masked form shows; for
     a short one, every short substring. The value is replaced by <SECRET> on every line of the
     context. A value that cannot be located means no lines at all (fail closed).
  2. Generic. Key formats (built-in shapes, plus policy.yaml's value patterns), random-looking
     tokens, passwords inside web addresses, and every string literal on a finding's own line
     are replaced too.
Callers only ever get redacted text back: no function here returns a raw value.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from securegate.entropy import shannon_entropy
from securegate.mask import fingerprint
from securegate.policy import Policy

VALUE_MARK = "<SECRET>"
REDACTED = "<REDACTED>"
STRING = "<STRING>"
OWN_RULE_PREFIX = "securegate-"  # our Semgrep rules point at code, not at a secret value

MASK_SHOWS = 4  # mask.mask_value keeps the first and last 4 characters of a long value
LONG_VALUE = 16  # values this long or longer are masked as abcd****wxyz; shorter ones as ****
MAX_SEARCH_LINE = 400  # longer lines are not searched (and so never sent)
RANDOM_LENGTH = 16
RANDOM_ENTROPY = 3.5

# Token ends: a value runs until whitespace, a quote or a closing bracket.
_TAIL = r"""[^\s"'`,;)\]}>]*"""
# Key shapes, unanchored, so they are found inside a line. None of these is a key itself.
_BUILT_IN = (
    r"acme_(?:live|test)_",
    r"[sr]k_(?:live|test)_",
    r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}",
    r"ABSK[A-Za-z0-9+/]{20,}",
    r"bedrock-api-key-",
    r"gh[pousr]_[A-Za-z0-9]{8,}",
    r"github_pat_",
    r"xox[abposr]-",
    r"-{5}BEGIN[A-Z0-9 _-]*PRIVATE KEY-{5}",
)
_EDGE = r"(?<![A-Za-z0-9_])"
KEY_SHAPES = tuple(re.compile(_EDGE + shape + _TAIL) for shape in _BUILT_IN)
_URL_PASSWORD = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@\"']+:[^\s/@\"']+@")
_RANDOM_TOKEN = re.compile(rf"[A-Za-z0-9+/=_\-.~]{{{RANDOM_LENGTH},}}")
_STRING_LITERAL = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\])*)\1""")
_INLINE_FLAGS = re.compile(r"^\(\?[aiLmsux]+\)")


@dataclass(frozen=True)
class Target:
    """A finding whose value must disappear from the context: what its report says about it."""

    line: int  # where the value starts, counted from 1
    masked_value: str  # as mask.mask_value made it: abcd****wxyz, or **** for a short value
    fingerprint: str  # mask.fingerprint of the value, 64 hex characters
    rule: str = ""  # the scanner rule; our own Semgrep rules point at code, not at a secret

    @property
    def points_at_code(self) -> bool:
        return self.rule.startswith(OWN_RULE_PREFIX)


def policy_patterns(policy: Policy) -> tuple[re.Pattern[str], ...]:
    """policy.yaml's value patterns from the rules that block or warn, made to match anywhere in
    a line and to cover the whole token. Placeholder patterns (an "ignore" rule) are left out:
    a placeholder is not a secret."""
    patterns = []
    for rule in policy.rules:
        if rule.decision == "ignore":
            continue
        for pattern in rule.conditions.value_patterns:
            patterns.append(_unanchored(pattern.pattern))
    return tuple(patterns)


def redact_context(
    lines: Sequence[str],
    first_line: int,
    targets: Iterable[Target],
    key: bytes,
    patterns: Sequence[re.Pattern[str]] = (),
) -> list[str] | None:
    """`lines` (the first is line `first_line` of its file) with every secret taken out, or None
    when a finding's value cannot be located: then nothing of these lines may be sent."""
    values: list[str] = []
    finding_lines: set[int] = set()
    for target in targets:
        index = target.line - first_line
        if not 0 <= index < len(lines):
            continue
        finding_lines.add(index)
        if target.points_at_code:
            continue
        value = _locate(lines[index], target, key)
        if value is None:
            return None
        values.append(value)
    redacted = list(lines)
    for value in sorted(set(values), key=len, reverse=True):
        redacted = [line.replace(value, VALUE_MARK) for line in redacted]
    for index in finding_lines:
        redacted[index] = _STRING_LITERAL.sub(_literal, redacted[index])
    return [redact_text(line, patterns) for line in redacted]


def redact_text(text: str, patterns: Sequence[re.Pattern[str]] = ()) -> str:
    """The generic layer: key shapes, passwords in web addresses and random-looking tokens."""
    text = _URL_PASSWORD.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    for pattern in (*KEY_SHAPES, *patterns):
        text = pattern.sub(REDACTED, text)
    return _RANDOM_TOKEN.sub(_random_or_kept, text)


def looks_secret(text: str, patterns: Sequence[re.Pattern[str]] = ()) -> bool:
    """Whether the generic layer would take anything out of `text`."""
    return redact_text(text, patterns) != text


def contains_value(lines: Iterable[str], target: Target, key: bytes) -> bool | None:
    """Whether a finding's value is on any of `lines`, such as the newest version of its file.
    None for a short value: searching every short substring of a whole file would be slow."""
    masked = target.masked_value
    if not (len(masked) == 2 * MASK_SHOWS + 4 and masked[MASK_SHOWS : MASK_SHOWS + 4] == "****"):
        return None
    start = masked[:MASK_SHOWS]
    return any(start in line and _locate(line, target, key) is not None for line in lines)


def _locate(line: str, target: Target, key: bytes) -> str | None:
    """The value on `line` whose fingerprint is the target's, or None."""
    if len(line) > MAX_SEARCH_LINE:
        return None
    masked = target.masked_value
    if len(masked) == 2 * MASK_SHOWS + 4 and masked[MASK_SHOWS : MASK_SHOWS + 4] == "****":
        start, end = masked[:MASK_SHOWS], masked[-MASK_SHOWS:]
        for i in _positions(line, start):
            for j in _positions(line, end):
                candidate = line[i : j + MASK_SHOWS]
                if len(candidate) >= LONG_VALUE and _same(candidate, target, key):
                    return candidate
        return None
    for length in range(LONG_VALUE - 1, 0, -1):
        for i in range(len(line) - length + 1):
            candidate = line[i : i + length]
            if _same(candidate, target, key):
                return candidate
    return None


def _same(candidate: str, target: Target, key: bytes) -> bool:
    return fingerprint(candidate, key) == target.fingerprint


def _positions(line: str, part: str) -> list[int]:
    return [m.start() for m in re.finditer(re.escape(part), line)] if part else []


def _literal(match: re.Match[str]) -> str:
    quote, content = match.group(1), match.group(2)
    return match.group(0) if content in ("", VALUE_MARK) else f"{quote}{STRING}{quote}"


def _random_or_kept(match: re.Match[str]) -> str:
    token = match.group(0)
    kinds = sum(any(test(c) for c in token) for test in (str.islower, str.isupper, str.isdigit))
    if kinds >= 2 and shannon_entropy(token) >= RANDOM_ENTROPY:
        return REDACTED
    return token


def _unanchored(pattern: str) -> re.Pattern[str]:
    """A whole-value pattern such as ^acme_live_ or ^AKIA...$, made to find the whole token
    anywhere in a line. Inline flags such as (?i) stay in front, where Python needs them."""
    flags = ""
    found = _INLINE_FLAGS.match(pattern)
    if found:
        flags, pattern = found.group(0), pattern[found.end() :]
    pattern = pattern.removeprefix("^").removesuffix("$")
    return re.compile(f"{flags}{_EDGE}(?:{pattern}){_TAIL}")
