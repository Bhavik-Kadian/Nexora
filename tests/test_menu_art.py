"""The menu's art and colours: the art fits the window, and colour only appears where it can."""

import io

import pytest

from securegate.menu import art
from securegate.menu.terminal import RED, can_show, paint, plain, wants_color

ALPHABETS = {"big": art.BIG, "slim": art.SLIM, "ascii": art.ASCII}


@pytest.mark.parametrize("letters", ALPHABETS.values(), ids=ALPHABETS.keys())
def test_every_letter_is_a_rectangle_of_the_same_height(
    letters: dict[str, tuple[str, ...]],
) -> None:
    assert set(art.NAME) <= set(letters)
    assert len({len(rows) for rows in letters.values()}) == 1
    for rows in letters.values():
        assert len({len(row) for row in rows}) == 1


def test_the_padlock_is_a_rectangle_at_least_as_tall_as_the_letters() -> None:
    assert len({len(row) for row in art.PADLOCK}) == 1
    assert all(len(art.PADLOCK) >= len(rows) for rows in (art.BIG["S"], art.SLIM["S"]))


@pytest.mark.parametrize("unicode", [True, False], ids=["unicode", "ascii"])
@pytest.mark.parametrize("width", [10, 30, 40, 52, 60, 83, 95, 96, 120, 200])
def test_the_art_fits_the_window(width: int, unicode: bool) -> None:
    banner = art.banner(width, unicode=unicode)
    assert banner.width <= width
    assert all(len(line) <= width for line in art.render(banner, color=False))


def test_a_wide_window_gets_the_padlock_beside_the_big_letters() -> None:
    first = art.render(art.banner(120, unicode=True), color=False)[0]
    assert first.startswith(art.PADLOCK[0] + art.GAP + art.BIG["S"][0])


def test_narrower_windows_get_smaller_art() -> None:
    widths = [art.banner(width, unicode=True).width for width in (120, 90, 60, 45, 20)]
    assert widths == sorted(widths, reverse=True)
    assert len(set(widths)) == len(widths)


def test_terminals_without_block_characters_get_ascii_art() -> None:
    lines = art.render(art.banner(120, unicode=False), color=False)
    assert len(lines) == len(art.ASCII["S"])
    assert all(line.isascii() for line in lines)


@pytest.mark.parametrize("width", [120, 90, 60, 45])
def test_colour_is_added_around_the_art_without_changing_it(width: int) -> None:
    banner = art.banner(width, unicode=True)
    colored = art.render(banner, color=True)
    assert any("\x1b[38;2;" in line for line in colored)
    assert [plain(line) for line in colored] == art.render(banner, color=False)


def test_no_escape_codes_when_colour_is_off() -> None:
    assert not any(
        "\x1b" in line for line in art.render(art.banner(120, unicode=True), color=False)
    )
    assert paint("BLOCK", RED, on=False) == "BLOCK"
    assert plain(paint("BLOCK", RED, on=True)) == "BLOCK"


class Stream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def test_colour_only_for_a_terminal_that_shows_it() -> None:
    assert wants_color(Stream(tty=True), {}, enable_ansi=lambda: True)
    assert not wants_color(Stream(tty=True), {}, enable_ansi=lambda: False)  # console refused
    assert not wants_color(Stream(tty=False), {}, enable_ansi=lambda: True)  # a file or pipe


@pytest.mark.parametrize("environ", [{"NO_COLOR": "1"}, {"TERM": "dumb"}])
def test_no_colour_when_the_environment_asks_for_none(environ: dict[str, str]) -> None:
    assert not wants_color(Stream(tty=True), environ, enable_ansi=lambda: True)


def test_block_letters_need_an_encoding_that_has_them() -> None:
    assert can_show("█╗", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert not can_show("█╗", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
