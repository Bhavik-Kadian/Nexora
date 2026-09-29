"""Masking, fingerprints and the fingerprint key.

Convention: raw test values never appear inside an assert (pytest prints assert operands).
"""

import dataclasses
import hashlib
import hmac
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import random_key, random_text
from securegate.errors import ConfigError
from securegate.mask import (
    HIDDEN,
    KEY_ENV_VAR,
    LOCAL_KEY_FILE,
    MaskedSecret,
    fingerprint,
    load_hmac_key,
    mask_value,
    protect,
)

# --- masking ---------------------------------------------------------------------------------


@pytest.mark.parametrize("length", range(16))
def test_values_shorter_than_16_are_fully_hidden(length: int) -> None:
    masked = mask_value(random_text(length))
    assert masked == HIDDEN


@pytest.mark.parametrize("length", [16, 17, 40, 200])
def test_long_values_show_only_first_4_and_last_4(length: int) -> None:
    raw = random_text(length)
    expected = raw[:4] + HIDDEN + raw[-4:]

    masked = mask_value(raw)
    middle_visible = raw[4:-4] in masked

    assert masked == expected
    assert len(masked) == 4 + len(HIDDEN) + 4
    assert not middle_visible


def test_boundary_between_fully_hidden_and_partly_shown() -> None:
    masked_15 = mask_value(random_text(15))
    masked_16 = mask_value(random_text(16))
    assert masked_15 == HIDDEN
    assert masked_16[4:8] == HIDDEN
    assert len(masked_16) == 12


def test_non_printable_edge_characters_show_as_question_marks() -> None:
    raw = "\n\t" + random_text(20) + "é\r"
    masked = mask_value(raw)
    assert masked[:2] == "??"
    assert masked[-2:] == "??"
    assert masked.isascii()
    assert masked.isprintable()


# --- fingerprints ----------------------------------------------------------------------------


def test_fingerprint_is_hmac_sha256_of_the_value() -> None:
    raw, key = random_text(40), random_key()
    expected = hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
    assert fingerprint(raw, key) == expected


def test_fingerprint_depends_on_both_key_and_value() -> None:
    raw, key = random_text(40), random_key()
    same_again = fingerprint(raw, key) == fingerprint(raw, key)
    other_key = fingerprint(raw, key) == fingerprint(raw, random_key())
    other_value = fingerprint(raw, key) == fingerprint(raw + "x", key)
    assert (same_again, other_key, other_value) == (True, False, False)


def test_fingerprint_accepts_unpaired_surrogates() -> None:
    result = fingerprint("\ud800" + random_text(20), random_key())
    assert len(result) == 64


def test_protect_gives_masked_value_fingerprint_and_12_character_id() -> None:
    raw, key = random_text(32), random_key()
    expected_masked, expected_fingerprint = mask_value(raw), fingerprint(raw, key)

    secret = protect(raw, key)

    assert secret.masked == expected_masked
    assert secret.fingerprint == expected_fingerprint
    assert secret.id == expected_fingerprint[:12]


def test_masked_secret_cannot_be_created_directly() -> None:
    with pytest.raises(TypeError, match=r"protect\(\)"):
        MaskedSecret("any text", "0" * 64)


def test_masked_secret_cannot_be_rewritten_with_replace() -> None:
    secret = protect(random_text(32), random_key())
    with pytest.raises(TypeError, match=r"protect\(\)"):
        dataclasses.replace(secret, masked="something else")


# --- the fingerprint key ---------------------------------------------------------------------


def test_environment_key_is_used_when_set(tmp_path: Path) -> None:
    env_key = random_text(40)
    state_dir = tmp_path / ".securegate"

    key_matches = load_hmac_key({KEY_ENV_VAR: env_key}, state_dir) == env_key.encode()

    assert key_matches
    assert not state_dir.exists()


def test_short_environment_key_is_refused(tmp_path: Path) -> None:
    short_key = random_text(31)
    with pytest.raises(ConfigError, match=KEY_ENV_VAR) as caught:
        load_hmac_key({KEY_ENV_VAR: short_key}, tmp_path)
    key_in_message = short_key in str(caught.value)
    assert not key_in_message


def test_empty_environment_key_is_refused_not_ignored(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=KEY_ENV_VAR):
        load_hmac_key({KEY_ENV_VAR: ""}, tmp_path)


def test_key_file_is_created_once_and_reused(tmp_path: Path) -> None:
    state_dir = tmp_path / ".securegate"

    same_key_twice = load_hmac_key({}, state_dir) == load_hmac_key({}, state_dir)

    stored = (state_dir / LOCAL_KEY_FILE).read_text(encoding="utf-8").strip()
    assert same_key_twice
    assert len(stored) == 64
    assert all(ch in "0123456789abcdef" for ch in stored)


def test_state_folder_tells_git_to_ignore_it(tmp_path: Path) -> None:
    state_dir = tmp_path / ".securegate"
    load_hmac_key({}, state_dir)
    lines = (state_dir / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "*" in lines


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_does_not_see_the_key_file_in_any_repo(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    load_hmac_key({}, tmp_path / ".securegate")
    status = subprocess.run(
        ["git", "-C", str(tmp_path), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no POSIX file modes")
def test_key_file_is_readable_by_owner_only(tmp_path: Path) -> None:
    state_dir = tmp_path / ".securegate"
    load_hmac_key({}, state_dir)
    mode = stat.S_IMODE((state_dir / LOCAL_KEY_FILE).stat().st_mode)
    assert mode == 0o600


def test_damaged_key_file_is_refused(tmp_path: Path) -> None:
    state_dir = tmp_path / ".securegate"
    state_dir.mkdir()
    (state_dir / LOCAL_KEY_FILE).write_text("too short\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="damaged"):
        load_hmac_key({}, state_dir)
