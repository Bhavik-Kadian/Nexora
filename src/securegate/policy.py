"""The policy engine: the only place that decides block / warn / ignore.

policy.yaml lists rules. They are checked top to bottom and the FIRST rule that matches decides.
A rule matches when every condition under `when` is true (AND); inside one list, any single
entry is enough (OR). A rule without `when` matches everything. The last rule must be like
that, so every finding gets a decision.
"""

import difflib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from securegate.errors import ConfigError
from securegate.finding import DECISIONS, SEVERITIES, Decision, Severity

POLICY_VERSION = 1
TOP_KEYS = ("version", "rules")
RULE_KEYS = ("name", "when", "decision", "severity", "reason", "remediation")
CONDITION_KEYS = ("value_matches", "path_matches", "rule_ids", "min_entropy")


@dataclass(frozen=True, slots=True)
class Conditions:
    value_patterns: tuple[re.Pattern[str], ...] = ()
    path_patterns: tuple[re.Pattern[str], ...] = ()
    rule_ids: frozenset[str] = frozenset()
    min_entropy: float | None = None

    @property
    def matches_everything(self) -> bool:
        return not (self.value_patterns or self.path_patterns or self.rule_ids) and (
            self.min_entropy is None
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    name: str
    conditions: Conditions
    decision: Decision
    severity: Severity
    reason: str
    remediation: str


@dataclass(frozen=True, slots=True)
class Policy:
    rules: tuple[PolicyRule, ...]
    source: str  # where the policy came from, for messages


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the policy decided for one finding."""

    rule_name: str
    decision: Decision
    severity: Severity
    reason: str
    remediation: str


# --- deciding --------------------------------------------------------------------------------


def decide(policy: Policy, *, rule_id: str, path: str, value: str, entropy: float) -> Verdict:
    """Return the verdict of the first matching rule.

    `value` is the raw secret. It is only tested against the value_matches regexes here and is
    never stored or returned.
    """
    for rule in policy.rules:
        if _matches(rule.conditions, rule_id=rule_id, path=path, value=value, entropy=entropy):
            return Verdict(
                rule_name=rule.name,
                decision=rule.decision,
                severity=rule.severity,
                reason=f"{rule.name}: {rule.reason}",
                remediation=rule.remediation,
            )
    # parse_policy() guarantees a catch-all last rule; fail closed if that is ever broken.
    raise ConfigError(f"{policy.source}: no rule matched; the last rule must have no 'when'")


def _matches(
    conditions: Conditions, *, rule_id: str, path: str, value: str, entropy: float
) -> bool:
    if conditions.rule_ids and rule_id not in conditions.rule_ids:
        return False
    if conditions.path_patterns and not any(p.fullmatch(path) for p in conditions.path_patterns):
        return False
    if conditions.min_entropy is not None and entropy < conditions.min_entropy:
        return False
    return not conditions.value_patterns or any(p.search(value) for p in conditions.value_patterns)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Turn a path glob into a regex that must match the whole path.

    **/  any number of folders, including none        *  any characters inside one name
    **   anything, including "/"                      ?  one character inside a name
    """
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(parts))


# --- loading and validating ------------------------------------------------------------------


def load_policy(path: Path) -> Policy:
    """Read and validate a policy file. Any problem raises ConfigError (exit code 2)."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"policy file not found: {path}") from None
    except OSError as err:
        raise ConfigError(f"cannot read policy file {path}: {err}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise ConfigError(f"{path} is not valid YAML: {_describe_yaml_error(err)}") from None
    return parse_policy(data, source=str(path))


def parse_policy(data: object, source: str = "policy.yaml") -> Policy:
    """Validate already-parsed YAML and build a Policy."""
    if not isinstance(data, Mapping):
        raise ConfigError(f"{source}: expected 'version: {POLICY_VERSION}' and a 'rules:' list")
    _reject_unknown_keys(data, TOP_KEYS, where=source)
    if data.get("version") != POLICY_VERSION:
        raise ConfigError(f"{source}: 'version' must be {POLICY_VERSION}")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ConfigError(f"{source}: 'rules' must be a list with at least one rule")

    rules = tuple(_parse_rule(item, n, source) for n, item in enumerate(raw_rules, start=1))

    names = [rule.name for rule in rules]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise ConfigError(f"{source}: rule names must be unique; repeated: {', '.join(repeated)}")
    for n, rule in enumerate(rules[:-1], start=1):
        if rule.conditions.matches_everything:
            raise ConfigError(
                f"{source}: rule #{n} ('{rule.name}') has no 'when', so it matches everything "
                "and the rules after it can never be used. Only the last rule may omit 'when'."
            )
    if not rules[-1].conditions.matches_everything:
        raise ConfigError(
            f"{source}: the last rule ('{rules[-1].name}') must have no 'when', so that every "
            "finding gets a decision. Add a final catch-all rule."
        )
    return Policy(rules=rules, source=source)


def _parse_rule(item: object, number: int, source: str) -> PolicyRule:
    if not isinstance(item, Mapping):
        raise ConfigError(f"{source}: rule #{number} must have name, decision and severity")
    name = item.get("name")
    label = f"{source}: rule #{number}" + (f" ('{name}')" if isinstance(name, str) else "")
    _reject_unknown_keys(item, RULE_KEYS, where=label)
    if not isinstance(name, str) or not name.strip():
        raise ConfigError(f"{label}: 'name' must be a non-empty text")
    decision = item.get("decision")
    if decision not in DECISIONS:
        raise ConfigError(f"{label}: 'decision' must be one of: {', '.join(DECISIONS)}")
    severity = item.get("severity")
    if severity not in SEVERITIES:
        raise ConfigError(f"{label}: 'severity' must be one of: {', '.join(SEVERITIES)}")
    return PolicyRule(
        name=name.strip(),
        conditions=_parse_conditions(item["when"], label) if "when" in item else Conditions(),
        decision=decision,
        severity=severity,
        reason=_optional_text(item, "reason", label) or f"matched policy rule '{name.strip()}'",
        remediation=_optional_text(item, "remediation", label),
    )


def _parse_conditions(raw: object, label: str) -> Conditions:
    if not isinstance(raw, Mapping) or not raw:
        raise ConfigError(
            f"{label}: 'when' must list at least one of {', '.join(CONDITION_KEYS)}. "
            "To match everything, remove 'when' instead."
        )
    where = f"{label}, under 'when'"
    _reject_unknown_keys(raw, CONDITION_KEYS, where=where)
    return Conditions(
        value_patterns=tuple(
            _compile_regex(p, where) for p in _text_list(raw, "value_matches", where)
        ),
        path_patterns=tuple(
            _compile_glob(p, where) for p in _text_list(raw, "path_matches", where)
        ),
        rule_ids=frozenset(_text_list(raw, "rule_ids", where)),
        min_entropy=_min_entropy(raw, where),
    )


def _text_list(raw: Mapping[object, object], key: str, where: str) -> list[str]:
    """A list of non-empty texts. A single text is accepted as a one-item list."""
    if key not in raw:
        return []
    value = raw[key]
    items = [value] if isinstance(value, str) else value
    if (
        not isinstance(items, list)
        or not items
        or not all(isinstance(entry, str) and entry.strip() for entry in items)
    ):
        raise ConfigError(f"{where}: '{key}' must be a list of non-empty texts")
    return [entry.strip() for entry in items]


def _compile_regex(pattern: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as err:
        raise ConfigError(
            f"{where}: value_matches entry '{pattern}' is not a valid regular expression ({err})"
        ) from None


def _compile_glob(pattern: str, where: str) -> re.Pattern[str]:
    if "\\" in pattern or pattern.startswith("/"):
        raise ConfigError(
            f"{where}: path_matches entry '{pattern}' must use '/' between folders and be "
            "relative to the scanned folder (no leading '/')"
        )
    return glob_to_regex(pattern)


def _min_entropy(raw: Mapping[object, object], where: str) -> float | None:
    if "min_entropy" not in raw:
        return None
    value = raw["min_entropy"]
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise ConfigError(f"{where}: 'min_entropy' must be a number of 0 or more, like 3.5")
    return float(value)


def _optional_text(item: Mapping[object, object], key: str, label: str) -> str:
    if key not in item:
        return ""
    value = item[key]
    if not isinstance(value, str):
        raise ConfigError(f"{label}: '{key}' must be text")
    return " ".join(value.split())


def _reject_unknown_keys(
    mapping: Mapping[object, object], allowed: Sequence[str], where: str
) -> None:
    for key in mapping:
        if key not in allowed:
            close = difflib.get_close_matches(str(key), allowed, n=1)
            hint = f" (did you mean '{close[0]}'?)" if close else ""
            raise ConfigError(
                f"{where}: unknown key '{key}'{hint}. Allowed keys: {', '.join(allowed)}"
            )


def _describe_yaml_error(err: yaml.YAMLError) -> str:
    mark = getattr(err, "problem_mark", None)
    problem = getattr(err, "problem", None) or "syntax error"
    if mark is None:
        return str(problem)
    return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
