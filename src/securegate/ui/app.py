"""The dashboard's pages: a small, read-only Flask app that shows one findings.json.

The report is read again on every request, so a new scan shows up after a reload. Pages run
no JavaScript, and the Content-Security-Policy header forbids scripts outright.
"""

from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request
from flask.typing import ResponseReturnValue

from securegate import __version__
from securegate.finding import DECISIONS
from securegate.ui.fixes import how_to_fix
from securegate.ui.report_view import FINDING_ID, ReportProblem, load_report

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

    @app.get("/findings")
    def findings() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        requested = request.args.get("decision")
        decision = requested if requested in DECISIONS else None
        return render_template(
            "findings.html",
            report=report,
            decision=decision,
            unknown_filter=requested if requested is not None and decision is None else None,
            rows=report.filtered(decision),
            active="findings",
        )

    @app.get("/findings/<finding_id>")
    def finding(finding_id: str) -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        places = report.by_id(finding_id) if FINDING_ID.fullmatch(finding_id) else []
        if not places:
            message = f"There is no finding with id “{finding_id[:40]}” in this report."
            return render_template("not_found.html", message=message, active="findings"), 404
        return render_template(
            "finding.html", places=places, fix=how_to_fix(places[0]), active="findings"
        )

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
