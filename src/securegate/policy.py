"""The policy engine: the only place that decides block / warn / ignore.

policy.yaml lists rules. They are checked top to bottom and the FIRST rule that matches decides.
A rule matches when every condition under `when` is true (AND); inside one list, any single
entry is enough (OR). A rule without `when` matches everything. The last rule must be like
that, so every finding gets a decision. Rules may carry their `number` from SecureGate's policy
table; reports then name them as "rule 8: provider-keys".
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from securegate.errors import ConfigError
from securegate.finding import DECISIONS, SEVERITIES, VALIDITIES, Decision, Severity, Validity
from securegate.validate import did_you_mean, load_yaml_file, reject_unknown_keys

POLICY_VERSION = 1
TOP_KEYS = ("version", "rules")
RULE_KEYS = ("number", "name", "when", "decision", "severity", "reason", "remediation")
CONDITION_KEYS = ("value_matches", "path_matches", "rule_ids", "min_entropy", "validity")


@dataclass(frozen=True, slots=True)
class Conditions:
    value_patterns: tuple[re.Pattern[str], ...] = ()
    path_patterns: tuple[re.Pattern[str], ...] = ()
    rule_ids: frozenset[str] = frozenset()
    min_entropy: float | None = None
    validity: frozenset[str] = frozenset()

    @property
    def matches_everything(self) -> bool:
        return not (
            self.value_patterns or self.path_patterns or self.rule_ids or self.validity
        ) and (self.min_entropy is None)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    name: str
    conditions: Conditions
    decision: Decision
    severity: Severity
    reason: str
    remediation: str
    number: int | None = None  # the rule's number in SecureGate's policy table


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
    number: int | None = None

    @property
    def label(self) -> str:
        """How reports name the rule: "rule 8: provider-keys", or just its name."""
        return f"rule {self.number}: {self.rule_name}" if self.number else self.rule_name


# --- deciding --------------------------------------------------------------------------------


def decide(
    policy: Policy,
    *,
    rule_id: str,
    path: str,
    value: str,
    entropy: float,
    validity: Validity = "not_checked",
) -> Verdict:
    """Return the verdict of the first matching rule.

    `value` is the raw secret. It is only tested against the value_matches regexes here and is
    never stored or returned.
    """
    for rule in policy.rules:
        if _matches(
            rule.conditions,
            rule_id=rule_id,
            path=path,
            value=value,
            entropy=entropy,
            validity=validity,
        ):
            return Verdict(
                rule_name=rule.name,
                decision=rule.decision,
                severity=rule.severity,
                reason=f"{rule.name}: {rule.reason}",
                remediation=rule.remediation,
                number=rule.number,
            )
    # parse_policy() guarantees a catch-all last rule; fail closed if that is ever broken.
    raise ConfigError(f"{policy.source}: no rule matched; the last rule must have no 'when'")


def _matches(
    conditions: Conditions,
    *,
    rule_id: str,
    path: str,
    value: str,
    entropy: float,
    validity: str,
) -> bool:
    if conditions.rule_ids and rule_id not in conditions.rule_ids:
        return False
    if conditions.validity and validity not in conditions.validity:
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
    return parse_policy(load_yaml_file(path, "policy file"), source=str(path))


def parse_policy(data: object, source: str = "policy.yaml") -> Policy:
    """Validate already-parsed YAML and build a Policy."""
    if not isinstance(data, Mapping):
        raise ConfigError(f"{source}: expected 'version: {POLICY_VERSION}' and a 'rules:' list")
    reject_unknown_keys(data, TOP_KEYS, where=source)
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
    _check_numbers(rules, source)
    for n, rule in enumerate(rules[:-1], start=1):
        if rule.conditions.matches_everything:
            raise ConfigError(
                f"{source}: {_rule_ref(n, rule.number)} ('{rule.name}') has no 'when', so it "
                "matches everything and the rules after it can never be used. Only the last "
                "rule may omit 'when'."
            )
    if not rules[-1].conditions.matches_everything:
        raise ConfigError(
            f"{source}: the last rule ('{rules[-1].name}') must have no 'when', so that every "
            "finding gets a decision. Add a final catch-all rule."
        )
    return Policy(rules=rules, source=source)


def _rule_ref(position: int, number: object) -> str:
    """How messages point at a rule: by its table number ("rule 10"), like the reports do, or
    by its place in the file ("rule #6") when it has no valid number."""
    if isinstance(number, int) and not isinstance(number, bool) and number >= 1:
        return f"rule {number}"
    return f"rule #{position}"


def _parse_rule(item: object, position: int, source: str) -> PolicyRule:
    if not isinstance(item, Mapping):
        raise ConfigError(f"{source}: rule #{position} must have name, decision and severity")
    name = item.get("name")
    ref = _rule_ref(position, item.get("number"))
    label = f"{source}: {ref}" + (f" ('{name}')" if isinstance(name, str) else "")
    reject_unknown_keys(item, RULE_KEYS, where=label)
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
        number=_number(item, label),
    )


def _number(item: Mapping[object, object], label: str) -> int | None:
    if "number" not in item:
        return None
    value = item["number"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{label}: 'number' must be a whole number of 1 or more, like 8")
    return value


def _check_numbers(rules: tuple[PolicyRule, ...], source: str) -> None:
    """Numbers are optional, but then every rule has one, and they go up from top to bottom
    (gaps are fine: the table's other rules may come later)."""
    numbered = [(rule.name, rule.number) for rule in rules if rule.number is not None]
    if not numbered:
        return
    if len(numbered) != len(rules):
        unnumbered = [rule.name for rule in rules if rule.number is None]
        raise ConfigError(
            f"{source}: either every rule has a 'number' or none does; missing on: "
            f"{', '.join(unnumbered)}"
        )
    for (name_before, before), (name_after, after) in pairwise(numbered):
        if after <= before:
            raise ConfigError(
                f"{source}: rule numbers must go up from top to bottom, but '{name_after}' "
                f"(number {after}) comes after '{name_before}' (number {before})"
            )


def _parse_conditions(raw: object, label: str) -> Conditions:
    if not isinstance(raw, Mapping) or not raw:
        raise ConfigError(
            f"{label}: 'when' must list at least one of {', '.join(CONDITION_KEYS)}. "
            "To match everything, remove 'when' instead."
        )
    where = f"{label}, under 'when'"
    reject_unknown_keys(raw, CONDITION_KEYS, where=where)
    return Conditions(
        value_patterns=tuple(
            _compile_regex(p, where) for p in _text_list(raw, "value_matches", where)
        ),
        path_patterns=tuple(
            _compile_glob(p, where) for p in _text_list(raw, "path_matches", where)
        ),
        rule_ids=frozenset(_text_list(raw, "rule_ids", where)),
        min_entropy=_min_entropy(raw, where),
        validity=frozenset(_validity(entry, where) for entry in _text_list(raw, "validity", where)),
    )


def _validity(entry: str, where: str) -> str:
    if entry not in VALIDITIES:
        raise ConfigError(
            f"{where}: validity '{entry}' is unknown{did_you_mean(entry, VALIDITIES)}. "
            f"Use one of: {', '.join(VALIDITIES)}"
        )
    return entry


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
