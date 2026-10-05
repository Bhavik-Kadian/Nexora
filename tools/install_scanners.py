"""Install the merge gate's scanners at the versions the workflow pins (make scanners).

The versions come from the env block at the top of .github/workflows/secret-gate.yml, so this
laptop and GitHub run the same tools:
  * Semgrep and Bandit are installed with pip into the Python that runs this script (.venv);
  * TruffleHog comes from its GitHub release. The release's list of checksums must match the
    pinned SHA-256, the archive must match its line in that list, and then only the program is
    taken out of the archive, into this Python's scripts folder (.venv/Scripts or .venv/bin),
    where SecureGate looks for it.
Nothing is piped into a shell, and nothing outside .venv changes.
"""

import argparse
import hashlib
import io
import os
import platform
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "secret-gate.yml"
RELEASES = "https://github.com/trufflesecurity/trufflehog/releases/download"
PINS = ("TRUFFLEHOG_VERSION", "TRUFFLEHOG_CHECKSUMS_SHA256", "SEMGREP_VERSION", "BANDIT_VERSION")
SYSTEMS = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
MACHINES = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
DOWNLOAD_TIMEOUT = 300  # seconds


class InstallError(Exception):
    """Something is wrong; nothing half-checked was installed."""


def read_pins(workflow_text: str) -> dict[str, str]:
    """The tool versions from the workflow's top-level env block."""
    data = yaml.safe_load(workflow_text)
    env = data.get("env") if isinstance(data, Mapping) else None
    if not isinstance(env, Mapping):
        raise InstallError(f"{WORKFLOW.name} has no env block at the top")
    missing = [name for name in PINS if not isinstance(env.get(name), str) or not env[name]]
    if missing:
        raise InstallError(f"{WORKFLOW.name} does not pin: {', '.join(missing)}")
    return {name: env[name] for name in PINS}


def asset_name(version: str, system: str, machine: str) -> str:
    """The release archive for this computer, such as trufflehog_3.97.9_windows_amd64.tar.gz."""
    os_name = SYSTEMS.get(system.lower())
    arch = MACHINES.get(machine.lower())
    if os_name is None or arch is None:
        raise InstallError(f"TruffleHog has no release for {system} on {machine}")
    return f"trufflehog_{version}_{os_name}_{arch}.tar.gz"


def checked_archive_sha(checksums: bytes, pinned_sha: str, asset: str) -> str:
    """Check the list of checksums against the pin, then return the archive's checksum."""
    if hashlib.sha256(checksums).hexdigest() != pinned_sha.lower():
        raise InstallError(
            "the TruffleHog checksums file does not match the SHA-256 pinned in the workflow"
        )
    found = [
        parts[0].lower()
        for parts in (line.split() for line in checksums.decode("utf-8").splitlines())
        if len(parts) == 2 and parts[1] == asset
    ]
    if len(found) != 1:
        raise InstallError(f"the TruffleHog checksums file has no single line for {asset}")
    return found[0]


def program_from_archive(archive: bytes, expected_sha: str, program: str) -> bytes:
    """The program inside the archive, after checking the archive's checksum.

    Only a regular file named exactly `program` at the top of the archive is read; nothing is
    extracted to disk by tarfile, so names like ../x cannot write outside the target folder.
    """
    if hashlib.sha256(archive).hexdigest() != expected_sha:
        raise InstallError("the TruffleHog archive does not match its checksum")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        members = [m for m in tar.getmembers() if m.name == program and m.isfile()]
        if len(members) != 1:
            raise InstallError(f"the TruffleHog archive has no single file named {program}")
        handle = tar.extractfile(members[0])
        if handle is None:
            raise InstallError(f"cannot read {program} from the TruffleHog archive")
        return handle.read()


def install_program(data: bytes, folder: Path, program: str) -> Path:
    """Write the program into `folder`, replacing an older copy only when complete."""
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / program
    fd, temp_name = tempfile.mkstemp(prefix=f".{program}.", dir=folder)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(temp_name, 0o700)  # owner only: run, read, replace
        os.replace(temp_name, target)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
    return target


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise InstallError(f"refusing to download over plain HTTP: {url}")
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:  # noqa: S310 - https only
        return response.read()


def install_trufflehog(pins: Mapping[str, str]) -> Path:
    version = pins["TRUFFLEHOG_VERSION"]
    asset = asset_name(version, platform.system(), platform.machine())
    release = f"{RELEASES}/v{version}"
    checksums = download(f"{release}/trufflehog_{version}_checksums.txt")
    expected = checked_archive_sha(checksums, pins["TRUFFLEHOG_CHECKSUMS_SHA256"], asset)
    program = "trufflehog.exe" if os.name == "nt" else "trufflehog"
    data = program_from_archive(download(f"{release}/{asset}"), expected, program)
    return install_program(data, Path(sysconfig.get_path("scripts")), program)


def install_python_tools(pins: Mapping[str, str]) -> None:
    packages = [f"semgrep=={pins['SEMGREP_VERSION']}", f"bandit=={pins['BANDIT_VERSION']}"]
    subprocess.run([sys.executable, "-m", "pip", "install", *packages], check=True)  # noqa: S603


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-pip", action="store_true", help="do not install Semgrep/Bandit")
    parser.add_argument("--skip-trufflehog", action="store_true", help="do not install TruffleHog")
    args = parser.parse_args(argv)
    try:
        pins = read_pins(WORKFLOW.read_text(encoding="utf-8"))
        if not args.skip_pip:
            install_python_tools(pins)
        if not args.skip_trufflehog:
            target = install_trufflehog(pins)
            print(f"TruffleHog {pins['TRUFFLEHOG_VERSION']} (checksums verified): {target}")
    except (InstallError, OSError, subprocess.CalledProcessError) as err:
        print(f"install_scanners: error: {err}", file=sys.stderr)
        return 2
    if not args.skip_pip:
        print(f"Semgrep {pins['SEMGREP_VERSION']} and Bandit {pins['BANDIT_VERSION']}: installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
