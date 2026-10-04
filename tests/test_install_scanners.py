"""make scanners (tools/install_scanners.py): pins, checked downloads, safe unpacking."""

import hashlib
import importlib.util
import io
import re
import tarfile
from pathlib import Path

import pytest

from helpers import REPO_ROOT


def load_installer():  # type: ignore[no-untyped-def]
    path = REPO_ROOT / "tools" / "install_scanners.py"
    spec = importlib.util.spec_from_file_location("install_scanners", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSTALLER = load_installer()
WORKFLOW_TEXT = INSTALLER.WORKFLOW.read_text(encoding="utf-8")


def archive_with(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_the_workflow_pins_every_scanner() -> None:
    pins = INSTALLER.read_pins(WORKFLOW_TEXT)
    assert set(pins) == set(INSTALLER.PINS)
    assert re.fullmatch(r"[0-9a-f]{64}", pins["TRUFFLEHOG_CHECKSUMS_SHA256"])
    assert all(
        re.fullmatch(r"\d+\.\d+\.\d+", pins[name]) for name in INSTALLER.PINS if "VERSION" in name
    )


def test_claude_md_names_the_pinned_versions() -> None:
    claude = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    pins = INSTALLER.read_pins(WORKFLOW_TEXT)
    for tool in ("TruffleHog", "Semgrep", "Bandit"):
        assert f"{tool} {pins[tool.upper() + '_VERSION']}" in claude


def test_a_missing_pin_is_refused() -> None:
    with pytest.raises(INSTALLER.InstallError, match="does not pin: BANDIT_VERSION"):
        INSTALLER.read_pins(WORKFLOW_TEXT.replace("BANDIT_VERSION", "BANDIT_VER"))


@pytest.mark.parametrize(
    ("system", "machine", "asset"),
    [
        ("Windows", "AMD64", "trufflehog_1.2.3_windows_amd64.tar.gz"),
        ("Linux", "x86_64", "trufflehog_1.2.3_linux_amd64.tar.gz"),
        ("Darwin", "arm64", "trufflehog_1.2.3_darwin_arm64.tar.gz"),
        ("Linux", "aarch64", "trufflehog_1.2.3_linux_arm64.tar.gz"),
    ],
)
def test_the_right_archive_for_this_computer(system: str, machine: str, asset: str) -> None:
    assert INSTALLER.asset_name("1.2.3", system, machine) == asset


def test_an_unknown_computer_is_refused() -> None:
    with pytest.raises(INSTALLER.InstallError, match="no release for Plan9"):
        INSTALLER.asset_name("1.2.3", "Plan9", "mips")


def test_the_checksums_file_must_match_the_pin_before_it_is_used() -> None:
    checksums = b"aa  trufflehog_1.2.3_linux_amd64.tar.gz\n"
    with pytest.raises(INSTALLER.InstallError, match="does not match the SHA-256 pinned"):
        INSTALLER.checked_archive_sha(checksums, "0" * 64, "trufflehog_1.2.3_linux_amd64.tar.gz")


def test_the_archive_checksum_comes_from_its_own_line() -> None:
    asset = "trufflehog_1.2.3_linux_amd64.tar.gz"
    checksums = f"{'a' * 64}  trufflehog_1.2.3_darwin_amd64.tar.gz\n{'b' * 64}  {asset}\n".encode()
    assert INSTALLER.checked_archive_sha(checksums, sha(checksums), asset) == "b" * 64
    with pytest.raises(INSTALLER.InstallError, match="no single line"):
        INSTALLER.checked_archive_sha(checksums, sha(checksums), "trufflehog_1.2.3_x.tar.gz")


def test_only_the_program_is_taken_from_a_checked_archive() -> None:
    archive = archive_with({"LICENSE": b"text", "../evil": b"no", "trufflehog": b"PROGRAM"})
    assert INSTALLER.program_from_archive(archive, sha(archive), "trufflehog") == b"PROGRAM"


def test_an_archive_with_the_wrong_checksum_is_refused() -> None:
    archive = archive_with({"trufflehog": b"PROGRAM"})
    with pytest.raises(INSTALLER.InstallError, match="does not match its checksum"):
        INSTALLER.program_from_archive(archive, "0" * 64, "trufflehog")


def test_an_archive_without_the_program_is_refused() -> None:
    archive = archive_with({"docs/trufflehog": b"PROGRAM"})
    with pytest.raises(INSTALLER.InstallError, match="no single file named trufflehog"):
        INSTALLER.program_from_archive(archive, sha(archive), "trufflehog")


def test_the_program_is_written_whole(tmp_path: Path) -> None:
    target = INSTALLER.install_program(b"PROGRAM", tmp_path / "bin", "trufflehog")
    assert target.read_bytes() == b"PROGRAM"
    assert [p.name for p in target.parent.iterdir()] == ["trufflehog"]  # no temporary left


def test_plain_http_downloads_are_refused() -> None:
    with pytest.raises(INSTALLER.InstallError, match="plain HTTP"):
        INSTALLER.download("http://example.com/trufflehog.tar.gz")
