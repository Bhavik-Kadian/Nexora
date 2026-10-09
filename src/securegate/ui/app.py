"""The dashboard's pages: a small, read-only Flask app that shows one findings.json.

The report is read again on every request, so a new scan shows up after a reload. Pages run
no JavaScript, and the Content-Security-Policy header forbids scripts outright. The findings
can be downloaded as CSV, JSON or a Markdown summary, and /report shows everything on one
page, ready to print. /advice shows the AI agents' advice, when the report has some that
passed its checks.
"""

from datetime import datetime
from pathlib import Path

from flask import Flask, Response, render_template, request
from flask.typing import ResponseReturnValue

from securegate import __version__
from securegate.finding import DECISIONS, SEVERITIES
from securegate.outputs.markdown import VERDICT_WORDS
from securegate.summary import render_summary
from securegate.ui.export import download_name, findings_csv, findings_json
from securegate.ui.fixes import how_to_fix
from securegate.ui.report_view import FINDING_ID, FindingView, ReportProblem, load_report

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
        blocked = sorted(
            report.filtered("block"), key=lambda f: (SEVERITIES.index(f.severity), f.file, f.line)
        )  # the most severe first
        return render_template("overview.html", report=report, blocked=blocked, active="overview")

    @app.get("/findings")
    def findings() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        requested = request.args.get("decision")
        decision = _decision()
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
        advice = report.advice
        return render_template(
            "finding.html",
            places=places,
            fix=how_to_fix(places[0]),
            ai_note=advice.triage_for(finding_id) if advice else None,
            ai_fix=advice.fix_for(finding_id) if advice else None,
            ai_model=advice.model if advice else None,
            verdict_words=VERDICT_WORDS,
            active="findings",
        )

    @app.get("/advice")
    def advice_page() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        places: dict[str, FindingView] = {}
        for found in report.findings:
            places.setdefault(found.id, found)
        advice = report.advice
        notes = [(places[n.finding], n) for n in advice.triage] if advice else []
        fixes = [(places[f.finding], f) for f in advice.fixes] if advice else []
        return render_template(
            "advice.html",
            report=report,
            advice=advice,
            advice_note=report.advice_note,
            notes=notes,
            fixes=fixes,
            verdict_words=VERDICT_WORDS,
            active="advice",
        )

    @app.get("/report")
    def full_report() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        items = [(f, how_to_fix(f)) for f in report.findings]
        return render_template("report.html", report=report, items=items, active="report")

    @app.get("/export/findings.csv")
    def export_csv() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        decision = _decision()
        csv_text = findings_csv(report.filtered(decision))
        return _download(csv_text, "text/csv", download_name(report, ".csv", decision))

    @app.get("/export/findings.json")
    def export_json() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        decision = _decision()
        json_text = findings_json(report, report.filtered(decision), decision=decision)
        return _download(json_text, "application/json", download_name(report, ".json", decision))

    @app.get("/export/summary.md")
    def export_summary() -> ResponseReturnValue:
        report = load_report(report_path)
        if isinstance(report, ReportProblem):
            return _problem_page(report)
        name = download_name(report, "-summary.md")
        return _download(render_summary(report), "text/markdown", name)

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


def _decision() -> str | None:
    """The ?decision= filter of this request, or None for all findings (also when unknown)."""
    requested = request.args.get("decision")
    return requested if requested in DECISIONS else None


def _download(text: str, mimetype: str, name: str) -> Response:
    """A file to save rather than a page to show. `name` holds only safe characters."""
    return Response(
        text,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _problem_page(problem: ReportProblem) -> ResponseReturnValue:
    """No usable report: explain what is wrong and how to create one."""
    return render_template("no_report.html", problem=problem), 503


def _local_time(value: datetime) -> str:
    return value.astimezone().strftime("%d %b %Y, %H:%M")


def _iso_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
