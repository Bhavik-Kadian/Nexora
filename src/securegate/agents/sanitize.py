"""Making an AI agent's answer safe to show: plain text, nothing shaped like a secret.

An agent's answer is untrusted text: the code it read may have told it what to say. So before
any of it is stored or shown, it becomes one line of plain text with no control characters, no
HTML, no links and no @mentions (which would ping people on GitHub), anything shaped like a
secret is replaced by ****, and it is cut at its length limit. Code an agent suggests is
refused instead of cleaned: it is applied to files, so it must already be right.
"""

import re
from collections.abc import Sequence

from securegate.agents.redact import REDACTED, STRING, VALUE_MARK, looks_secret, redact_text

HIDDEN = "****"
ELLIPSIS = "…"
MAX_PASSES = 5
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_TAG = re.compile(r"<[^<>]{0,200}>")
_MARKDOWN_LINK = re.compile(r"\[([^\]]{0,200})\]\([^)]{0,500}\)")
# A link runs to the next space, but punctuation at its end is the sentence's, not the link's.
_LINK = re.compile(r"""(?i)(?:\b(?:https?|ftp|file)://|\bwww\.)[^\s<>]*[^\s<>.,;:!?)\]'"]""")
_MENTION = re.compile(r"(?<![\w.@])@(?=[A-Za-z0-9])")
_CODE_LINE = re.compile(r"[ -~\t]*")  # printable ASCII and tabs only


def clean_text(value: str, limit: int, patterns: Sequence[re.Pattern[str]] = ()) -> str:
    """One line of plain text, safe to show anywhere, at most `limit` characters long."""
    text = _CONTROL.sub(" ", value)
    for _ in range(MAX_PASSES):  # removing a tag or a link can join what was around it into one
        before = text
        text = _MARKDOWN_LINK.sub(r"\1", text)
        text = _LINK.sub("(link removed)", text)
        text = _TAG.sub("", text)
        if text == before:
            break
    else:
        text = text.replace("<", "").replace(">", "")
    text = _MENTION.sub("", text)
    text = redact_text(text, patterns).replace(REDACTED, HIDDEN)
    text = " ".join(text.split())
    if len(text) > limit:
        cut = text[: limit - len(ELLIPSIS)].rsplit(" ", 1)[0] or text[: limit - len(ELLIPSIS)]
        text = cut.rstrip() + ELLIPSIS
    return text


def clean_code(value: str, limit: int, patterns: Sequence[re.Pattern[str]] = ()) -> str | None:
    """A suggested line of code, or None when it cannot be used as it is: more than one line,
    longer than `limit`, characters other than printable ASCII, a leftover placeholder, a link,
    or anything shaped like a secret."""
    if not value or len(value) > limit or not _CODE_LINE.fullmatch(value):
        return None
    if VALUE_MARK in value or STRING in value or REDACTED in value or _LINK.search(value):
        return None
    if looks_secret(value, patterns):
        return None
    return value


def has_secret(value: str, patterns: Sequence[re.Pattern[str]] = ()) -> bool:
    """Whether text an agent wrote holds anything shaped like a secret."""
    return looks_secret(value, patterns)
