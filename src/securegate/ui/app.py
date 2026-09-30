"""The dashboard's pages: a small, read-only Flask app that shows one findings.json.

The report is read again on every request, so a new scan shows up after a reload. Pages run
no JavaScript, and the Content-Security-Policy header forbids scripts outright.
"""

from datetime import datetime
from pathlib import Path

from flask import Flask, render_template
from flask.typing import ResponseReturnValue

from securegate import __version__
from securegate.ui.report_view import ReportProblem, load_report

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(report_path: Path) -> Flask:
    """Build the dashboard for the report at `report_path`."""
    app = Flask(__name__)
    app.add_template_filter(_local_time, "local_time")
    app.add_template_filter(_iso_time, "iso_time")

    @app.context_processor
    def page_defaults() -> dict[str, object]:
        return {"version": __version__, "report_path": report_path, "active": None}

    @app.after_request
    def add_security_headers(response):  # type: ignore[no-untyped-def]
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/")
    def overview() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        return render_template("overview.html", report=report, active="overview")

    @app.get("/favicon.ico")
    def favicon() -> ResponseReturnValue:
        return "", 204

    @app.errorhandler(404)
    def not_found(_error: Exception) -> ResponseReturnValue:
        return render_template("not_found.html", message="This page does not exist."), 404

    @app.errorhandler(500)
    def server_error(_error: Exception) -> ResponseReturnValue:
        return render_template("error.html"), 500

    return app


def _problem_page(problem: ReportProblem) -> ResponseReturnValue:
    """No usable report: explain what is wrong and how to create one."""
    return render_template("no_report.html", problem=problem), 503


def _local_time(value: datetime) -> str:
    return value.astimezone().strftime("%d %b %Y, %H:%M")


def _iso_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
