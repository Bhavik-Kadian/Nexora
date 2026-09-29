"""Finding the external programs SecureGate runs (gitleaks, git)."""

import os
from pathlib import Path


def find_program(name: str, path_env: str | None = None) -> Path | None:
    """Find a program in the absolute folders listed in PATH, or return None.

    Relative entries such as "." are skipped: a scanned repository could contain a fake
    program, and Windows would otherwise run it from the current folder.
    """
    names = (f"{name}.exe", name) if os.name == "nt" else (name,)
    search = os.environ.get("PATH", "") if path_env is None else path_env
    for folder in search.split(os.pathsep):
        if not folder or not os.path.isabs(folder):
            continue
        for candidate_name in names:
            candidate = Path(folder) / candidate_name
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate
    return None
