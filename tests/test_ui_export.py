"""Downloads from the dashboard: the findings as CSV or JSON, and the Markdown summary.

Convention: raw test values never appear inside an assert; masked values may.
"""

import csv
import io
import json
from dataclasses import replace
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from helpers import leaked
from securegate.demo.generator import DemoResult
from securegate.summary import render_summary
from securegate.ui.app import create_app
from securegate.ui.export import CSV_COLUMNS, FORMULA_STARTS, download_name, findings_csv
from securegate.ui.report_view import ReportView, load_report

EXPORTS = ["/export/findings.csv", "/export/findings.json", "/export/summary.md"]


@pytest.fixture
def client(sample_report: Path) -> FlaskClient:
    return create_app(sample_report).test_client()


def report_data(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def csv_rows(text: str) -> list[dict[str, str]]:
    assert text.startswith("﻿")  # so that Excel reads it as UTF-8
    return list(csv.DictReader(io.StringIO(text.removeprefix("﻿"))))


def view(sample_report: Path) -> ReportView:
    report = load_report(sample_report)
    assert isinstance(report, ReportView)
    return report


# --- CSV -------------------------------------------------------------------------------------


def test_csv_has_a_header_and_one_row_per_finding(client: FlaskClient, sample_report: Path) -> None:
    response = client.get("/export/findings.csv")
    text = response.get_data(as_text=True)
    header, *rows = list(csv.reader(io.StringIO(text.removeprefix("﻿"))))

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert header == list(CSV_COLUMNS)
    assert len(rows) == len(report_data(sample_report)["findings"])


def test_csv_rows_hold_the_masked_values_and_the_policy_rule(
    client: FlaskClient, sample_report: Path
) -> None:
    rows = csv_rows(client.get("/export/findings.csv").get_data(as_text=True))
    masked = {row["masked_value"].removeprefix("'") for row in rows}
    assert masked == {f["masked_value"] for f in report_data(sample_report)["findings"]}
    assert {row["policy_rule"] for row in rows} >= {"provider-keys", "placeholders"}


def test_no_csv_cell_starts_like_a_spreadsheet_formula(client: FlaskClient) -> None:
    rows = csv_rows(client.get("/export/findings.csv").get_data(as_text=True))
    risky = [cell for row in rows for cell in row.values() if cell.startswith(FORMULA_STARTS)]
    private_key = next(row for row in rows if row["rule"] == "private-key")

    assert risky == []
    assert private_key["masked_value"] == "'----****----"  # stays text in a spreadsheet


@pytest.mark.parametrize("start", ["=", "+", "-", "@"])
def test_any_text_that_looks_like_a_formula_is_kept_as_text(
    sample_report: Path, start: str
) -> None:
    finding = replace(view(sample_report).findings[0], file=f"{start}SUM(A1:A9)")
    (row,) = csv_rows(findings_csv([finding]))
    assert row["file"] == f"'{start}SUM(A1:A9)"


# --- JSON ------------------------------------------------------------------------------------


def test_the_json_download_is_a_report_the_dashboard_can_read(
    client: FlaskClient, sample_report: Path, tmp_path: Path
) -> None:
    exported = tmp_path / "exported.json"
    exported.write_bytes(client.get("/export/findings.json").get_data())
    again = load_report(exported)
    original = view(sample_report)

    assert isinstance(again, ReportView)
    assert again.findings == original.findings
    assert (again.result, again.target, again.scanner_version, again.scanned_at) == (
        original.result,
        original.target,
        original.scanner_version,
        original.scanned_at,
    )


def test_the_json_download_says_where_it_came_from(client: FlaskClient) -> None:
    data = json.loads(client.get("/export/findings.json").get_data(as_text=True))
    assert data["exported"] == {"from": "findings.json", "decision": None}
    assert data["summary"]["total"] == len(data["findings"])


# --- filters, file names, the Markdown summary ------------------------------------------------


@pytest.mark.parametrize("decision", ["block", "warn", "ignore"])
def test_csv_and_json_follow_the_decision_filter(
    client: FlaskClient, sample_report: Path, decision: str
) -> None:
    expected = report_data(sample_report)["summary"][decision]
    rows = csv_rows(client.get(f"/export/findings.csv?decision={decision}").get_data(as_text=True))
    data = json.loads(client.get(f"/export/findings.json?decision={decision}").get_data())

    assert [row["decision"] for row in rows] == [decision] * expected
    assert [f["decision"] for f in data["findings"]] == [decision] * expected
    assert data["summary"]["total"] == expected
    assert data["exported"]["decision"] == decision


def test_an_unknown_filter_downloads_everything(client: FlaskClient, sample_report: Path) -> None:
    rows = csv_rows(client.get("/export/findings.csv?decision=maybe").get_data(as_text=True))
    assert len(rows) == len(report_data(sample_report)["findings"])


@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("/export/findings.csv", "findings.csv"),
        ("/export/findings.csv?decision=block", "findings-block.csv"),
        ("/export/findings.json?decision=warn", "findings-warn.json"),
        ("/export/summary.md", "findings-summary.md"),
    ],
)
def test_downloads_are_files_named_after_the_report(
    client: FlaskClient, path: str, name: str
) -> None:
    response = client.get(path)
    assert response.headers["Content-Disposition"] == f'attachment; filename="{name}"'
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    ("report_name", "expected"),
    [
        ("findings-demo.json", "findings-demo.csv"),
        ('my "odd" report;.json', "my-odd-report.csv"),
        ("....json", "findings.csv"),
    ],
)
def test_download_names_hold_only_safe_characters(
    sample_report: Path, report_name: str, expected: str
) -> None:
    renamed = replace(view(sample_report), path=Path(report_name))
    assert download_name(renamed, ".csv") == expected


def test_the_markdown_download_is_the_summary(client: FlaskClient, sample_report: Path) -> None:
    response = client.get("/export/summary.md")
    assert response.mimetype == "text/markdown"
    assert response.get_data(as_text=True) == render_summary(view(sample_report))


# --- masked values only -----------------------------------------------------------------------


def test_no_download_and_no_page_holds_a_planted_secret(
    client: FlaskClient, demo_repo: DemoResult
) -> None:
    paths = [*EXPORTS, "/report", "/", "/findings"]
    found = {
        path: leaked(demo_repo.planted, client.get(path).get_data(as_text=True)) for path in paths
    }
    assert found == {path: [] for path in paths}


@pytest.mark.parametrize("path", [*EXPORTS, "/report"])
def test_a_report_with_an_unmasked_value_is_never_downloaded(
    tmp_path: Path, sample_report: Path, path: str
) -> None:
    data = report_data(sample_report)
    data["findings"][0]["masked_value"] = "abcdefghijklmnopqrstuvwxyz"  # not the masked shape
    report = tmp_path / "findings.json"
    report.write_text(json.dumps(data), encoding="utf-8")

    response = create_app(report).test_client().get(path)

    assert response.status_code == 503
    assert "Content-Disposition" not in response.headers
    assert "abcdefghijklmnopqrstuvwxyz" not in response.get_data(as_text=True)
