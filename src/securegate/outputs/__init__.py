"""The reports SecureGate writes besides findings.json: the PR comment, the job summary and SARIF.

All three are made from findings.json read back through ui.report_view.load_report(), which
refuses any value that is not masked: an output can only ever hold what that check let through.
"""

from dataclasses import dataclass
from pathlib import Path

from securegate.errors import ConfigError
from securegate.outputs.markdown import render_comment, render_summary
from securegate.outputs.sarif import build_sarif
from securegate.report import write_json, write_text
from securegate.ui.report_view import ReportView, load_report


@dataclass(frozen=True)
class Targets:
    """Where to write each output; None means "not asked for"."""

    sarif: Path | None = None
    summary: Path | None = None
    comment: Path | None = None

    @property
    def any(self) -> bool:
        return any(path is not None for path in (self.sarif, self.summary, self.comment))


def write_outputs(report_path: Path, targets: Targets, *, finished: bool) -> None:
    """Write the outputs asked for, from the report at `report_path`.

    For a finished scan (exit code 0 or 1) the report must read back cleanly; if it does not,
    that is an error (fail closed). For a failed scan, the comment and summary say so, and any
    SARIF file is deleted: an empty one would tell GitHub that every earlier alert was fixed.
    """
    report = load_report(report_path)
    usable = isinstance(report, ReportView) and report.exit_code in (0, 1)
    if finished and not usable:
        raise ConfigError(f"the report {report_path} could not be read back to write the outputs")
    if targets.summary is not None:
        write_text(targets.summary, render_summary(report))
    if targets.comment is not None:
        write_text(targets.comment, render_comment(report))
    if targets.sarif is not None:
        if isinstance(report, ReportView) and usable:
            write_json(targets.sarif, build_sarif(report))
        else:
            try:
                targets.sarif.unlink(missing_ok=True)
            except OSError as err:
                raise ConfigError(f"cannot remove the old SARIF file: {err}") from None
