"""Helpers for checking YAML files that people edit by hand (policy.yaml, catalog.yaml)."""

import difflib
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from securegate.errors import ConfigError


def load_yaml_file(path: Path, what: str) -> object:
    """Read and parse a YAML file. Problems become a ConfigError naming `what` and the path."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"{what} not found: {path}") from None
    except OSError as err:
        raise ConfigError(f"cannot read {what} {path}: {err}") from None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise ConfigError(f"{path} is not valid YAML: {_describe_yaml_error(err)}") from None


def did_you_mean(word: str, choices: Sequence[str]) -> str:
    """A hint such as " (did you mean 'rules'?)" when a choice is close to `word`, else ""."""
    close = difflib.get_close_matches(word, choices, n=1)
    return f" (did you mean '{close[0]}'?)" if close else ""


def reject_unknown_keys(
    mapping: Mapping[object, object], allowed: Sequence[str], where: str
) -> None:
    """Stop at the first key that is not allowed, so typos never pass silently."""
    for key in mapping:
        if key not in allowed:
            raise ConfigError(
                f"{where}: unknown key '{key}'{did_you_mean(str(key), allowed)}. "
                f"Allowed keys: {', '.join(allowed)}"
            )


def _describe_yaml_error(err: yaml.YAMLError) -> str:
    mark = getattr(err, "problem_mark", None)
    problem = getattr(err, "problem", None) or "syntax error"
    if mark is None:
        return str(problem)
    return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
