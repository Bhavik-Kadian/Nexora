"""The menu's terminal: what it asks and shows, and colours where the terminal can show them.

Colour follows the usual conventions: only when the output is a terminal, and never when the
NO_COLOR environment variable is set (https://no-color.org) or TERM is "dumb". A Windows console
shows colours only after a program asks for them; if that fails, the menu stays plain.
"""

import os
import re
import shutil
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TextIO

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"
GREY = "\x1b[90m"
CLEAR = "\x1b[H\x1b[2J"  # cursor to the top left, then clear the screen
BLOCK_CHARACTERS = "█▀▄╔═╗"  # what the big letters need
ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

STD_OUTPUT_HANDLE = -11
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def _no_pause(_seconds: float) -> None:
    """Show the art at once (tests, and terminals without colour)."""


@dataclass(frozen=True)
class Terminal:
    """How the menu talks to the person at the keyboard. Tests pass a scripted one."""

    ask: Callable[[str], str]  # show a question, return what was typed
    say: Callable[[str], None]  # show one line
    columns: Callable[[], int]  # the window's width right now
    color: bool = False
    unicode: bool = True  # whether it can show the block letters
    pause: Callable[[float], None] = _no_pause


def real_terminal() -> Terminal:
    """This terminal: the keyboard, the screen, and colour if it can show it."""
    return Terminal(
        ask=input,
        say=print,
        columns=lambda: shutil.get_terminal_size().columns,
        color=wants_color(sys.stdout, os.environ),
        unicode=can_show(BLOCK_CHARACTERS, sys.stdout),
        pause=time.sleep,
    )


def wants_color(
    stream: TextIO,
    environ: Mapping[str, str],
    *,
    enable_ansi: Callable[[], bool] | None = None,
) -> bool:
    """Whether to colour what goes to `stream`."""
    if environ.get("NO_COLOR") or environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None or not isatty():
        return False
    return (enable_ansi or _enable_ansi)()


def _enable_ansi() -> bool:
    """Make sure the terminal turns ANSI escape codes into colours. On Windows, ask the console
    for it (Windows 10 and later); elsewhere, terminals do it by themselves."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        )
    except (OSError, AttributeError):
        return False


def can_show(text: str, stream: TextIO) -> bool:
    """Whether `stream` can show `text`: block letters need an encoding that has them."""
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def rgb(red: int, green: int, blue: int) -> str:
    """The escape code for a 24-bit text colour."""
    return f"\x1b[38;2;{red};{green};{blue}m"


def paint(text: str, style: str, *, on: bool) -> str:
    """`text` in `style` (escape codes such as BOLD + RED), or unchanged when colour is off."""
    return f"{style}{text}{RESET}" if on and style and text else text


def plain(text: str) -> str:
    """`text` without escape codes."""
    return ESCAPE.sub("", text)
