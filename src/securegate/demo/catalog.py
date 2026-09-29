"""The demo catalog (catalog.yaml): what to plant in the demo repo, and what SecureGate should
decide about each item. It is edited by hand, so every mistake gets a plain-language message."""

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath

from securegate.demo import fakes
from securegate.demo.app import BASE_FILES
from securegate.errors import ConfigError
from securegate.finding import DECISIONS, Decision
from securegate.validate import did_you_mean, load_yaml_file, reject_unknown_keys

TOP_KEYS = ("items",)
ITEM_KEYS = ("kind", "file", "placement", "expected", "name", "variant", "note")
PLACEMENTS = ("current", "history-only")
RESERVED_FILES = ("ground_truth.csv", ".securegate-demo")
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class CatalogItem:
    number: int  # position in catalog.yaml, starting at 1
    kind: str
    file: str
    placement: str
    expected: Decision
    name: str | None = None
    variant: str | None = None
    note: str | None = None

    @property
    def is_secret(self) -> bool:
        return self.kind in fakes.SECRET_KINDS


def default_catalog_path() -> Path:
    return Path(str(resources.files("securegate.demo").joinpath("catalog.yaml")))


def load_catalog(path: Path | None = None) -> list[CatalogItem]:
    """Read and validate a catalog file (the packaged catalog.yaml by default)."""
    path = path or default_catalog_path()
    return parse_catalog(load_yaml_file(path, "catalog file"), source=str(path))


def parse_catalog(data: object, source: str = "catalog.yaml") -> list[CatalogItem]:
    """Validate already-parsed YAML and return the items in file order."""
    if not isinstance(data, Mapping):
        raise ConfigError(f"{source}: expected an 'items:' list at the top")
    reject_unknown_keys(data, TOP_KEYS, where=source)
    raw_items = data.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ConfigError(f"{source}: 'items' must be a list with at least one item")
    items = [_parse_item(raw, n, source) for n, raw in enumerate(raw_items, start=1)]
    _check_files(items, source)
    return items


def _parse_item(raw: object, number: int, source: str) -> CatalogItem:
    where = f"{source}: item #{number}"
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{where} must have kind, file, placement and expected")
    reject_unknown_keys(raw, ITEM_KEYS, where=where)
    kind = _choice(raw, "kind", fakes.KINDS, where)
    file = _file_path(raw.get("file"), where)
    placement = _choice(raw, "placement", PLACEMENTS, where)
    expected = _choice(raw, "expected", DECISIONS, where)
    name = _optional_text(raw, "name", where)
    if name is not None and not NAME_PATTERN.fullmatch(name):
        raise ConfigError(f"{where}: 'name' must be a variable name such as STRIPE_SECRET_KEY")
    variant = _optional_text(raw, "variant", where)
    if variant is not None:
        if kind != "placeholder":
            raise ConfigError(f"{where}: 'variant' only applies to kind: placeholder")
        if variant not in fakes.PLACEHOLDER_VARIANTS:
            raise ConfigError(
                f"{where}: 'variant' must be one of {', '.join(fakes.PLACEHOLDER_VARIANTS)}"
                f"{did_you_mean(variant, fakes.PLACEHOLDER_VARIANTS)}"
            )
    if not fakes.fits(kind, fakes.file_type(file)):
        allowed = ", ".join(fakes.ONLY_IN[kind])
        raise ConfigError(f"{where}: kind {kind} cannot go in {file} (it fits: {allowed} files)")
    return CatalogItem(
        number=number,
        kind=kind,
        file=file,
        placement=placement,
        expected=expected,  # type: ignore[arg-type]  # checked by _choice above
        name=name,
        variant=variant,
        note=_optional_text(raw, "note", where),
    )


def _check_files(items: Sequence[CatalogItem], source: str) -> None:
    per_file = Counter(item.file for item in items)
    for item in items:
        where = f"{source}: item #{item.number} ({item.kind} in {item.file})"
        app_file = BASE_FILES.get(item.file)
        if app_file is not None and not app_file.plantable:
            raise ConfigError(f"{where}: this app file has no place for planted lines")
        if item.placement == "history-only":
            if app_file is not None:
                raise ConfigError(
                    f"{where}: a history-only item needs a file of its own, because the whole "
                    "file is deleted later; use a new file name"
                )
            if per_file[item.file] > 1:
                raise ConfigError(
                    f"{where}: a history-only item needs a file of its own, but other items "
                    "use the same file"
                )


def _choice(raw: Mapping[object, object], key: str, choices: Sequence[str], where: str) -> str:
    value = raw.get(key)
    if value not in choices:
        hint = did_you_mean(value, choices) if isinstance(value, str) else ""
        raise ConfigError(f"{where}: '{key}' must be one of: {', '.join(choices)}{hint}")
    return str(value)


def _file_path(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: 'file' must be a path such as config/settings.py")
    path = value.strip()
    parts = PurePosixPath(path).parts
    if (
        "\\" in path
        or path.startswith("/")
        or ":" in path
        or any(part in ("..", ".", ".git") for part in parts)
        or path in RESERVED_FILES
    ):
        raise ConfigError(
            f"{where}: 'file' must be a path inside the demo repo, using '/' between folders "
            "(no leading '/', no '..', not inside .git)"
        )
    return path


def _optional_text(raw: Mapping[object, object], key: str, where: str) -> str | None:
    if key not in raw or raw[key] is None:
        return None
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: '{key}' must be text")
    return value.strip()
