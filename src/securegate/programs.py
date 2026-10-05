"""Finding the external programs SecureGate runs (gitleaks, trufflehog, git, gh)."""

import os
import sysconfig
from pathlib import Path


def find_program(name: str, path_env: str | None = None) -> Path | None:
    """Find a program in the absolute folders listed in PATH, or return None.

    Relative entries such as "." are skipped: a scanned repository could contain a fake
    program, and Windows would otherwise run it from the current folder. A real lookup (no
    `path_env`) also tries the scripts folder of the running Python (.venv/Scripts), where
    `make scanners` puts TruffleHog: that folder belongs to SecureGate's own environment.
    """
    names = (f"{name}.exe", name) if os.name == "nt" else (name,)
    search = os.environ.get("PATH", "") if path_env is None else path_env
    folders = search.split(os.pathsep)
    if path_env is None:
        folders.append(sysconfig.get_path("scripts"))
    for folder in folders:
        if not folder or not os.path.isabs(folder):
            continue
        for candidate_name in names:
            candidate = Path(folder) / candidate_name
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate
    return None
