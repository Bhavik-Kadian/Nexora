"""The AI agents' advice, as stored in findings.json under "advice", and its checks.

The section is additive (schema_version stays 1): reports without it read as before. Every text
in it was cleaned by sanitize.clean_text when it was written, and is checked again whenever a
report is read (parse_advice): the right types, known finding ids, within the length limits, no
markup, no links and nothing shaped like a secret. Advice that fails a check is withheld as a
whole, with a note saying so; the findings themselves are not affected.
"""

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field

from securegate.agents.sanitize import has_secret
from securegate.finding import SEVERITIES

STATUSES = ("ok", "skipped", "failed")
AGENTS = ("triage", "fix", "incident")
VERDICTS = ("likely_real", "likely_false_alarm", "needs_a_human")
CONFIDENCES = ("low", "medium", "high")
LIMITS = {
    "note": 300,
    "model": 100,
    "why": 400,
    "next_step": 300,
    "replacement": 300,
    "import_line": 120,
    "exposure": 600,
    "title": 120,
    "detail": 500,
    "notify": 300,
}
MAX_ITEMS = 50
MAX_STEPS = 10
ENV_VAR = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
FINDING_ID = re.compile(r"[0-9a-f]{12}")
MADE_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f]|<[^<>]*>|(?i:https?://|www\.)|(?<![\w.@])@\w")
_UNSAFE_CODE = re.compile(r"[^ -~]|(?i:https?://)")


class AdviceError(ValueError):
    """The advice in a report breaks a rule. The message never quotes the advice."""


@dataclass(frozen=True)
class TriageNote:
    finding: str  # the finding's id
    verdict: str  # likely_real, likely_false_alarm or needs_a_human
    confidence: str  # low, medium or high
    why: str
    next_step: str


@dataclass(frozen=True)
class FixSuggestion:
    finding: str
    env_var: str  # the environment variable the code should read instead
    replacement: str  # the finding's line, rewritten to read it
    import_line: str | None  # an import the replacement needs, such as "import os"
    why: str


@dataclass(frozen=True)
class Step:
    title: str
    detail: str


@dataclass(frozen=True)
class IncidentPlan:
    severity: str
    exposure: str  # who could see the key, and since when
    steps: tuple[Step, ...]
    notify: str


@dataclass(frozen=True)
class AgentStatus:
    status: str  # ok, skipped or failed
    note: str | None = None


@dataclass(frozen=True)
class Advice:
    status: str  # ok when at least one agent answered; skipped or failed otherwise
    note: str | None
    model: str | None
    made_at: str | None  # when the agents answered, UTC
    agents: Mapping[str, AgentStatus] = field(default_factory=dict)
    triage: tuple[TriageNote, ...] = ()
    fixes: tuple[FixSuggestion, ...] = ()
    incident: IncidentPlan | None = None

    def triage_for(self, finding_id: str) -> TriageNote | None:
        return next((note for note in self.triage if note.finding == finding_id), None)

    def fix_for(self, finding_id: str) -> FixSuggestion | None:
        return next((fix for fix in self.fixes if fix.finding == finding_id), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "note": self.note,
            "model": self.model,
            "made_at": self.made_at,
            "agents": {
                name: {"status": result.status, "note": result.note}
                for name, result in self.agents.items()
            },
            "triage": [
                {
                    "finding": n.finding,
                    "verdict": n.verdict,
                    "confidence": n.confidence,
                    "why": n.why,
                    "next_step": n.next_step,
                }
                for n in self.triage
            ],
            "fixes": [
                {
                    "finding": f.finding,
                    "env_var": f.env_var,
                    "replacement": f.replacement,
                    "import_line": f.import_line,
                    "why": f.why,
                }
                for f in self.fixes
            ],
            "incident": None
            if self.incident is None
            else {
                "severity": self.incident.severity,
                "exposure": self.incident.exposure,
                "steps": [{"title": s.title, "detail": s.detail} for s in self.incident.steps],
                "notify": self.incident.notify,
            },
        }


def parse_advice(raw: object, finding_ids: Collection[str]) -> Advice:
    """The advice section of a report, checked. Raises AdviceError."""
    data = _object(raw, "the advice")
    status = _choice(data.get("status"), STATUSES, "its status")
    agents_raw = _object(data.get("agents", {}), "its list of agents")
    agents = {}
    for name, value in agents_raw.items():
        if name not in AGENTS:
            raise AdviceError("it names an agent SecureGate does not have")
        item = _object(value, f"the {name} agent's status")
        agents[name] = AgentStatus(
            _choice(item.get("status"), STATUSES, f"the {name} agent's status"),
            _optional_text(item.get("note"), "note"),
        )
    made_at = data.get("made_at")
    if made_at is not None and not (isinstance(made_at, str) and MADE_AT.fullmatch(made_at)):
        raise AdviceError("its time is not in the expected format")
    return Advice(
        status=status,
        note=_optional_text(data.get("note"), "note"),
        model=_optional_text(data.get("model"), "model"),
        made_at=made_at,
        agents=agents,
        triage=tuple(_triage(item, finding_ids) for item in _list(data.get("triage", []))),
        fixes=tuple(_fix(item, finding_ids) for item in _list(data.get("fixes", []))),
        incident=None if data.get("incident") is None else _incident(data["incident"]),
    )


def _triage(raw: object, finding_ids: Collection[str]) -> TriageNote:
    item = _object(raw, "a triage note")
    return TriageNote(
        finding=_finding(item.get("finding"), finding_ids),
        verdict=_choice(item.get("verdict"), VERDICTS, "a triage verdict"),
        confidence=_choice(item.get("confidence"), CONFIDENCES, "a triage confidence"),
        why=_text(item.get("why"), "why"),
        next_step=_text(item.get("next_step"), "next_step"),
    )


def _fix(raw: object, finding_ids: Collection[str]) -> FixSuggestion:
    item = _object(raw, "a fix suggestion")
    env_var = item.get("env_var")
    if not (isinstance(env_var, str) and ENV_VAR.fullmatch(env_var)):
        raise AdviceError("a fix suggestion has an unusable environment variable name")
    import_line = item.get("import_line")
    return FixSuggestion(
        finding=_finding(item.get("finding"), finding_ids),
        env_var=env_var,
        replacement=_code(item.get("replacement"), "replacement"),
        import_line=None if import_line is None else _code(import_line, "import_line"),
        why=_text(item.get("why"), "why"),
    )


def _incident(raw: object) -> IncidentPlan:
    item = _object(raw, "the incident plan")
    steps = _list(item.get("steps"))
    if not steps or len(steps) > MAX_STEPS:
        raise AdviceError(f"the incident plan needs 1 to {MAX_STEPS} steps")
    return IncidentPlan(
        severity=_choice(item.get("severity"), SEVERITIES, "the incident's severity"),
        exposure=_text(item.get("exposure"), "exposure"),
        steps=tuple(
            Step(_text(step.get("title"), "title"), _text(step.get("detail"), "detail"))
            for step in (_object(s, "an incident step") for s in steps)
        ),
        notify=_text(item.get("notify"), "notify"),
    )


def _object(raw: object, what: str) -> Mapping[str, object]:
    if not isinstance(raw, dict):
        raise AdviceError(f"{what} is not an object")
    return raw


def _list(raw: object) -> list[object]:
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS:
        raise AdviceError(f"a list in it is not a list of at most {MAX_ITEMS} items")
    return raw


def _choice(value: object, allowed: tuple[str, ...], what: str) -> str:
    if value not in allowed:
        raise AdviceError(f"{what} is not one SecureGate knows")
    return value  # type: ignore[return-value]  # one of `allowed`, so a str


def _finding(value: object, finding_ids: Collection[str]) -> str:
    if not (isinstance(value, str) and FINDING_ID.fullmatch(value) and value in finding_ids):
        raise AdviceError("it refers to a finding that is not in the report")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > LIMITS[name]:
        raise AdviceError(f"a '{name}' text is missing or longer than {LIMITS[name]} characters")
    if _UNSAFE_TEXT.search(value):
        raise AdviceError(f"a '{name}' text holds markup, a link or a mention")
    if has_secret(value):
        raise AdviceError("it holds something shaped like a secret")
    return value


def _optional_text(value: object, name: str) -> str | None:
    return None if value is None else _text(value, name)


def _code(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > LIMITS[name]:
        raise AdviceError(f"a '{name}' line is missing or longer than {LIMITS[name]} characters")
    if _UNSAFE_CODE.search(value):
        raise AdviceError(f"a '{name}' line holds a character or a link it may not hold")
    if has_secret(value):
        raise AdviceError("it holds something shaped like a secret")
    return value
