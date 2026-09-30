"""Design rules the designers rely on: every colour, font size, spacing value and radius lives
in tokens.css, the required values are there, and text meets WCAG AA contrast."""

import re
from pathlib import Path

import pytest

import securegate.ui

CSS_DIR = Path(securegate.ui.__file__).parent / "static" / "css"
TOKENS = (CSS_DIR / "tokens.css").read_text(encoding="utf-8")
APP_CSS = (CSS_DIR / "app.css").read_text(encoding="utf-8")

COLOUR = re.compile(
    r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(|\b(?:black|white|red|green|blue|gr[ae]y|orange|yellow)\b"
)
LENGTH = re.compile(r"(?<![\w-])\d*\.?\d+(?:px|rem|em|pt|vh|vw)\b")
SIZED_PROPERTIES = re.compile(
    r"font-size|line-height|margin.*|padding.*|gap|row-gap|column-gap|.*radius|border.*|"
    r"outline.*|inset|top|left|right|bottom|letter-spacing|text-underline-offset|box-shadow"
)


def without_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def declarations(css: str) -> list[tuple[str, str]]:
    return re.findall(r"([a-z-]+)\s*:\s*([^;{}]+);", without_comments(css))


def base_tokens() -> dict[str, str]:
    """The tokens of the default (laptop) theme: the first :root block."""
    block = re.search(r":root\s*{(.*?)}", without_comments(TOKENS), flags=re.DOTALL)
    assert block is not None
    return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block.group(1)))


# --- app.css only uses tokens -------------------------------------------------------------


def test_app_css_has_no_raw_colours() -> None:
    raw = [f"{prop}: {value}" for prop, value in declarations(APP_CSS) if COLOUR.search(value)]
    assert raw == []


def test_app_css_has_no_raw_sizes_spacing_or_radii() -> None:
    raw = [
        f"{prop}: {value}"
        for prop, value in declarations(APP_CSS)
        if SIZED_PROPERTIES.fullmatch(prop) and LENGTH.search(value)
    ]
    assert raw == []


def test_app_css_fonts_come_from_tokens() -> None:
    families = [value for prop, value in declarations(APP_CSS) if prop == "font-family"]
    assert families and all(value.startswith("var(--") for value in families)


def test_every_variable_used_is_defined() -> None:
    used = set(re.findall(r"var\((--[\w-]+)\)", APP_CSS))
    assert sorted(used - set(base_tokens())) == []


# --- the values from the design brief ------------------------------------------------------


@pytest.mark.parametrize(
    ("token", "value"),
    [
        ("--color-neutral-background-2", "#FAFAFA"),  # page
        ("--color-neutral-background-1", "#FFFFFF"),  # cards
        ("--color-neutral-stroke-1", "#E0E0E0"),  # 1px borders
        ("--stroke-width-thin", "1px"),
        ("--border-radius-large", "8px"),
        ("--color-neutral-foreground-1", "#242424"),  # text
        ("--color-neutral-foreground-2", "#616161"),  # secondary text
        ("--color-brand-foreground-1", "#0F6CBD"),  # the one accent
        ("--font-family-base", '"Segoe UI", system-ui, sans-serif'),
        ("--font-size-base-300", "14px"),  # base size
    ],
)
def test_design_brief_values(token: str, value: str) -> None:
    assert base_tokens()[token] == value


def test_no_gradients_anywhere() -> None:
    assert "gradient(" not in APP_CSS + TOKENS


# --- contrast (WCAG 2.x) --------------------------------------------------------------------


def luminance(hex_colour: str) -> float:
    channels = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(foreground: str, background: str) -> float:
    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


TEXT_PAIRS = [
    ("--color-neutral-foreground-1", "--color-neutral-background-1"),
    ("--color-neutral-foreground-1", "--color-neutral-background-2"),
    ("--color-neutral-foreground-1", "--color-neutral-background-3"),
    ("--color-neutral-foreground-1", "--color-neutral-background-1-hover"),
    ("--color-neutral-foreground-2", "--color-neutral-background-1"),
    ("--color-neutral-foreground-2", "--color-neutral-background-2"),
    ("--color-neutral-foreground-2", "--color-neutral-background-3"),
    ("--color-neutral-foreground-2", "--color-brand-background-2"),
    ("--color-brand-foreground-1", "--color-neutral-background-1"),
    ("--color-brand-foreground-1", "--color-neutral-background-2"),
    ("--color-brand-foreground-1", "--color-brand-background-2"),
    ("--color-brand-foreground-1-hover", "--color-neutral-background-1"),
    ("--color-block-foreground", "--color-block-background"),
    ("--color-warn-foreground", "--color-warn-background"),
    ("--color-ignore-foreground", "--color-ignore-background"),
]
NON_TEXT_PAIRS = [  # focus outline and bars: WCAG asks 3:1 for these
    ("--color-stroke-focus", "--color-neutral-background-1"),
    ("--color-stroke-focus", "--color-neutral-background-2"),
    ("--color-brand-foreground-1", "--color-neutral-background-3"),
]


@pytest.mark.parametrize(("foreground", "background"), TEXT_PAIRS)
def test_text_meets_wcag_aa(foreground: str, background: str) -> None:
    tokens = base_tokens()
    assert contrast(tokens[foreground], tokens[background]) >= 4.5


@pytest.mark.parametrize(("foreground", "background"), NON_TEXT_PAIRS)
def test_focus_and_bars_meet_wcag_non_text_contrast(foreground: str, background: str) -> None:
    tokens = base_tokens()
    assert contrast(tokens[foreground], tokens[background]) >= 3.0
