"""The dashboard pages, driven by Flask's test client."""

import html
import json
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from helpers import Page
from securegate.ui.app import create_app
from securegate.ui.report_view import report_commands

PAGES = ["/", "/findings", "/findings?decision=block"]
DECISION_ORDER = {"block": 0, "warn": 1, "ignore": 2}


@pytest.fixture
def client(sample_report: Path) -> FlaskClient:
    return create_app(sample_report).test_client()


def report_data(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def body(response) -> str:  # type: ignore[no-untyped-def]
    return response.get_data(as_text=True)


def badges(page: Page) -> list[str]:
    """The decisions shown by the badges on a page, in order."""
    return [
        (attrs.get("class") or "").split("badge--")[1]
        for attrs in page.all("span")
        if "badge--" in (attrs.get("class") or "")
    ]


def row_links(page: Page) -> list[str]:
    return [attrs["href"] for attrs in page.all("a") if attrs.get("class") == "row-link"]


# --- the overview --------------------------------------------------------------------------


def test_overview_shows_the_totals_from_the_report(
    client: FlaskClient, sample_report: Path
) -> None:
    summary = report_data(sample_report)["summary"]
    response = client.get("/")
    page = Page(body(response))

    assert response.status_code == 200
    for label, key in [("Total findings", "total"), ("Blocked", "block"), ("Warnings", "warn"),
                       ("Ignored", "ignore")]:  # fmt: skip
        assert f"{label} {summary[key]}" in page.text


def test_overview_has_one_bar_per_severity(client: FlaskClient, sample_report: Path) -> None:
    findings = report_data(sample_report)["findings"]
    page = Page(body(client.get("/")))
    meters = page.all("meter")
    labels = {attrs["for"] for attrs in page.all("label")}

    assert [m["id"] for m in meters] == [f"severity-{s}" for s in
                                        ("critical", "high", "medium", "low", "info")]  # fmt: skip
    assert all(m["id"] in labels for m in meters)
    critical = sum(1 for f in findings if f["severity"] == "critical")
    assert meters[0]["value"] == str(critical)
    assert meters[0]["max"] == str(len(findings))


def test_overview_says_when_and_where_the_scan_ran(client: FlaskClient) -> None:
    page = Page(body(client.get("/")))
    datetimes = [attrs.get("datetime") for attrs in page.all("time")]

    assert "../securegate-demo" in page.text
    assert "The whole Git history" in page.text
    assert "Gitleaks 8.30.1" in page.text
    assert len(datetimes) == 1 and datetimes[0].endswith("Z")


# --- the findings list ---------------------------------------------------------------------


def test_findings_lists_every_finding_with_blocks_first(
    client: FlaskClient, sample_report: Path
) -> None:
    response = client.get("/findings")
    shown = badges(Page(body(response)))

    assert response.status_code == 200
    assert len(shown) == len(report_data(sample_report)["findings"])
    assert shown == sorted(shown, key=DECISION_ORDER.__getitem__)
    assert shown[0] == "block"


def test_findings_table_has_the_required_columns(client: FlaskClient) -> None:
    page = Page(body(client.get("/findings")))
    headers = page.text.split("Decision Rule File:line Masked value Reason")
    assert len(headers) == 2
    assert [th["scope"] for th in page.all("th")] == ["col"] * 5


@pytest.mark.parametrize("decision", ["block", "warn", "ignore"])
def test_filter_shows_only_that_decision(
    client: FlaskClient, sample_report: Path, decision: str
) -> None:
    response = client.get(f"/findings?decision={decision}")
    page = Page(body(response))
    current = [a["href"] for a in page.all("a") if a.get("aria-current") == "page"]

    assert response.status_code == 200
    assert badges(page) == [decision] * report_data(sample_report)["summary"][decision]
    assert current == ["/findings", f"/findings?decision={decision}"]  # tab, then filter


def test_unknown_filter_shows_everything_with_a_note(
    client: FlaskClient, sample_report: Path
) -> None:
    response = client.get("/findings?decision=maybe")
    page = Page(body(response))

    assert response.status_code == 200
    assert "There is no decision called “maybe”" in page.text
    assert len(badges(page)) == len(report_data(sample_report)["findings"])


def test_each_row_links_to_its_detail_page(client: FlaskClient, sample_report: Path) -> None:
    ids = {f["id"] for f in report_data(sample_report)["findings"]}
    links = row_links(Page(body(client.get("/findings"))))
    assert {link.removeprefix("/findings/") for link in links} == ids


def test_rows_show_rule_location_masked_value_and_reason(
    client: FlaskClient, sample_report: Path
) -> None:
    text = Page(body(client.get("/findings"))).text
    missing = [
        f["id"]
        for f in report_data(sample_report)["findings"]
        if not all(
            part in text for part in (f["rule"], f"{f['file']}:{f['line']}", f["masked_value"])
        )
    ]
    assert missing == []
    assert "provider-keys A payment, cloud or private key" in text


def test_an_empty_filter_says_so(tmp_path: Path, sample_report: Path) -> None:
    data = report_data(sample_report)
    data["findings"] = [f for f in data["findings"] if f["decision"] != "ignore"]
    report = tmp_path / "findings.json"
    report.write_text(json.dumps(data), encoding="utf-8")
    text = Page(body(create_app(report).test_client().get("/findings?decision=ignore"))).text
    assert "No findings with decision IGNORE." in text


# --- no usable report: a friendly page ------------------------------------------------------


@pytest.mark.parametrize("path", PAGES)
def test_missing_report_shows_the_command_that_creates_one(tmp_path: Path, path: str) -> None:
    report = tmp_path / "findings.json"
    response = create_app(report).test_client().get(path)
    text = html.unescape(body(response))

    assert response.status_code == 503
    assert "No scan report yet" in text
    assert report_commands(report)[0] in text
    assert "scan . --mode repo --out" in text


def test_missing_demo_report_points_to_the_make_targets() -> None:
    assert report_commands(Path("findings-demo.json")) == ("make demo", "make scan-demo")


@pytest.mark.parametrize(
    ("content", "title", "detail"),
    [
        ("{not json", "The scan report can't be read", "is not valid JSON"),
        ('{"tool": "other"}', "This report can't be shown", "not a SecureGate findings report"),
        (
            '{"tool": "securegate", "status": "error", "error": "Gitleaks was not found."}',
            "The last scan failed",
            "Gitleaks was not found.",
        ),
        (
            '{"tool": "securegate", "schema_version": 99, "findings": []}',
            "This report can't be shown",
            "different version of SecureGate",
        ),
    ],
)
def test_broken_reports_show_a_friendly_page(
    tmp_path: Path, content: str, title: str, detail: str
) -> None:
    report = tmp_path / "findings.json"
    report.write_text(content, encoding="utf-8")
    response = create_app(report).test_client().get("/")
    text = html.unescape(body(response))

    assert response.status_code == 503
    assert title in text
    assert detail in text


def test_a_report_with_an_unmasked_value_is_refused(tmp_path: Path, sample_report: Path) -> None:
    data = report_data(sample_report)
    data["findings"][0]["masked_value"] = "abcdefghijklmnopqrstuvwxyz"  # not the masked shape
    report = tmp_path / "findings.json"
    report.write_text(json.dumps(data), encoding="utf-8")

    response = create_app(report).test_client().get("/")
    text = body(response)

    assert response.status_code == 503
    assert "not masked" in text
    assert "abcdefghijklmnopqrstuvwxyz" not in text


# --- every page: safe and accessible --------------------------------------------------------


@pytest.mark.parametrize("path", PAGES)
def test_pages_are_script_free_with_strict_security_headers(client: FlaskClient, path: str) -> None:
    response = client.get(path)
    policy = response.headers["Content-Security-Policy"]

    assert "default-src 'none'" in policy
    assert "script-src" not in policy
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert Page(body(response)).all("script") == []


@pytest.mark.parametrize("path", PAGES)
def test_pages_have_accessible_structure(client: FlaskClient, path: str) -> None:
    page = Page(body(client.get(path)))

    assert page.all("html")[0].get("lang") == "en"
    assert len(page.all("h1")) == 1
    assert len(page.all("main")) == 1
    assert any(a.get("href") == "#main" for a in page.all("a"))
    assert all(nav.get("aria-label") for nav in page.all("nav"))
    assert all(th.get("scope") in ("col", "row") for th in page.all("th"))


def test_unknown_page_is_a_friendly_404(client: FlaskClient) -> None:
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert "Not found" in body(response)


def test_css_is_served_and_the_favicon_is_empty(client: FlaskClient) -> None:
    assert client.get("/static/css/tokens.css").status_code == 200
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/favicon.ico").status_code == 204
