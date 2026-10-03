"""The SecureGate banner: a padlock beside the name in big block letters.

banner() picks the biggest version that fits the window: the padlock with big letters, the big
letters alone, slim letters with or without the padlock, ASCII letters when the terminal cannot
show block characters, and the plain name when nothing else fits. render() turns it into lines
of text, in colour or not; the art itself is plain text.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from itertools import groupby

from securegate.menu.terminal import paint, rgb

NAME = "SECUREGATE"
TAGLINE = "Finds secrets in a Git project, masks them, and blocks the dangerous ones."
GAP = "  "  # between the padlock and the name

PADLOCK = (
    "  ▄█▀▀▀█▄  ",
    "  █     █  ",
    "███████████",
    "████   ████",
    "█████ █████",
    "▀█████████▀",
)

# Big letters in the "ANSI Shadow" style: the blocks are the letter, the lines its 3D shadow.
BIG: Mapping[str, tuple[str, ...]] = {
    "S": ("███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"),
    "E": ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    "C": (" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"),
    "U": ("██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    "R": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    "G": (" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    "A": (" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"),
    "T": ("████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "),
}
SHADOW = frozenset("╔╗╚╝═║")

# Slim letters: two rows of half blocks, for narrow windows.
SLIM: Mapping[str, tuple[str, ...]] = {
    "S": ("█▀▀", "▄▄█"),
    "E": ("█▀▀", "██▄"),
    "C": ("█▀▀", "█▄▄"),
    "U": ("█ █", "█▄█"),
    "R": ("█▀█", "█▀▄"),
    "G": ("█▀▀", "█▄█"),
    "A": ("▄▀█", "█▀█"),
    "T": ("▀█▀", " █ "),
}

# ASCII letters, for terminals that cannot show block characters.
ASCII: Mapping[str, tuple[str, ...]] = {
    "S": (" ___ ", "/ __|", "\\__ \\", "|___/"),
    "E": (" ___ ", "| __|", "| _| ", "|___|"),
    "C": ("  ___ ", " / __|", "| (__ ", " \\___|"),
    "U": (" _   _ ", "| | | |", "| |_| |", " \\___/ "),
    "R": (" ___ ", "| _ \\", "|   /", "|_|_\\"),
    "G": ("  ___ ", " / __|", "| (_ |", " \\___|"),
    "A": ("   _   ", "  /_\\  ", " / _ \\ ", "/_/ \\_\\"),
    "T": (" _____ ", "|_   _|", "  | |  ", "  |_|  "),
}

RGB = tuple[int, int, int]
PADLOCK_TOP: RGB = (255, 214, 0)  # gold
PADLOCK_BOTTOM: RGB = (255, 143, 0)  # amber
LETTERS_TOP: RGB = (0, 229, 255)  # cyan
LETTERS_BOTTOM: RGB = (41, 98, 255)  # blue
SHADOW_COLOR: RGB = (88, 96, 110)  # grey


def word(letters: Mapping[str, tuple[str, ...]], spacing: int = 0) -> tuple[str, ...]:
    """NAME written in `letters`, row by row."""
    glyphs = [letters[letter] for letter in NAME]
    return tuple(
        (" " * spacing).join(glyph[row] for glyph in glyphs) for row in range(len(glyphs[0]))
    )


@dataclass(frozen=True)
class Banner:
    """One version of the art: the padlock's rows (none without it) and the name's rows."""

    icon: tuple[str, ...]
    name: tuple[str, ...]

    @property
    def name_column(self) -> int:
        """Where the name starts, so that the tagline can line up with it."""
        return len(self.icon[0]) + len(GAP) if self.icon else 0

    @property
    def width(self) -> int:
        return self.name_column + max(len(row) for row in self.name)

    def layout(self) -> list[tuple[int | None, int | None]]:
        """For each line: the padlock row and the name row it shows (None: nothing). The
        shorter of the two is centred beside the taller one."""
        height = max(len(self.icon), len(self.name))
        return [
            (_centred(line, len(self.icon), height), _centred(line, len(self.name), height))
            for line in range(height)
        ]


def banner(width: int, *, unicode: bool) -> Banner:
    """The biggest version of the art that fits in `width` columns."""
    if unicode:
        choices = [
            Banner(PADLOCK, word(BIG)),
            Banner((), word(BIG)),
            Banner(PADLOCK, word(SLIM, spacing=1)),
            Banner((), word(SLIM, spacing=1)),
        ]
    else:
        choices = [Banner((), word(ASCII, spacing=1))]
    for choice in choices:
        if choice.width <= width:
            return choice
    return Banner((), ("SecureGate",))


def render(art: Banner, *, color: bool) -> list[str]:
    """The art as lines of text: in colour, a gold padlock and letters that fade from cyan to
    blue, with a grey shadow. Without colour, the same text with no escape codes."""
    icon_width = len(art.icon[0]) if art.icon else 0
    gap = GAP if art.icon else ""
    lines = []
    for icon_row, name_row in art.layout():
        icon = art.icon[icon_row] if icon_row is not None else " " * icon_width
        name = art.name[name_row] if name_row is not None else ""
        line = (icon + gap + name).rstrip()
        if color:
            line = _paint_icon(line[:icon_width], icon_row, len(art.icon)) + _paint_name(
                line[icon_width:], name_row, len(art.name)
            )
        lines.append(line)
    return lines


def _centred(line: int, rows: int, height: int) -> int | None:
    row = line - (height - rows) // 2
    return row if 0 <= row < rows else None


def _paint_icon(text: str, row: int | None, rows: int) -> str:
    if row is None:
        return text
    return paint(text, rgb(*_blend(PADLOCK_TOP, PADLOCK_BOTTOM, row, rows)), on=True)


def _paint_name(text: str, row: int | None, rows: int) -> str:
    if row is None:
        return text
    letters = rgb(*_blend(LETTERS_TOP, LETTERS_BOTTOM, row, rows))
    shadow = rgb(*SHADOW_COLOR)

    def style(character: str) -> str:
        if character == " ":
            return ""
        return shadow if character in SHADOW else letters

    return "".join(paint("".join(run), key, on=True) for key, run in groupby(text, key=style))


def _blend(top: RGB, bottom: RGB, row: int, rows: int) -> RGB:
    """The colour `row` rows down a fade from `top` to `bottom`."""
    share = row / (rows - 1) if rows > 1 else 0.0
    red, green, blue = (round(a + (b - a) * share) for a, b in zip(top, bottom, strict=True))
    return red, green, blue
