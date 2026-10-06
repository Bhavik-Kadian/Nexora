"""Layer 3, M1: nothing secret reaches an AI agent, and nothing unsafe comes back from one.

Every planted value is built at runtime; asserts compare booleans, never the values.
"""

import json
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from fake_gitleaks import FakeGitleaks, report_for_demo
from helpers import (
    GITLEAKS_CONFIG,
    POLICY_FILE,
    fake_acme_test_token,
    fake_acme_token,
    fake_aws_key_id,
    fake_github_token,
    fake_private_key,
    fake_stripe_key,
    git_installed,
    leaked,
    random_key,
    random_text,
)
from securegate.agents.advice import AdviceError, parse_advice
from securegate.agents.redact import (
    MAX_SEARCH_LINE,
    REDACTED,
    STRING,
    VALUE_MARK,
    Target,
    _unanchored,
    policy_patterns,
    redact_context,
    redact_text,
)
from securegate.agents.sanitize import clean_code, clean_text, has_secret
from securegate.demo.generator import DemoResult
from securegate.mask import fingerprint, mask_value
from securegate.pipeline import run_scan
from securegate.policy import load_policy
from securegate.ui.report_view import ReportView, load_report


def target(line: int, value: str, key: bytes, rule: str = "generic-api-key") -> Target:
    return Target(line, mask_value(value), fingerprint(value, key), rule)


def shown(lines: list[str] | None, *values: str) -> bool:
    """Whether any value, or the hidden middle of a long one, is in the lines."""
    text = "\n".join(lines or [])
    return any(v in text or (len(v) >= 16 and v[4:-4] in text) for v in values)


# --- the exact layer --------------------------------------------------------------------------


def test_a_long_value_is_found_by_its_fingerprint_and_removed_from_every_line() -> None:
    key, token = random_key(), fake_acme_token()
    lines = [
        '"""Charges a customer."""',
        "",
        f'ACME_PAY_API_KEY = "{token}"',
        "",
        f"# old key, kept for reference: {token}",
    ]
    out = redact_context(lines, 1, [target(3, token, key, "acme-pay-token")], key)
    assert out is not None
    assert not shown(out, token)
    assert out[2] == f'ACME_PAY_API_KEY = "{VALUE_MARK}"'
    assert VALUE_MARK in out[4]


def test_a_short_value_is_found_too() -> None:
    key, password = random_key(), random_text(9)
    lines = ["import os", f'DB_PASSWORD = "{password}"', 'DB_USER = "payments"']
    out = redact_context(lines, 10, [target(11, password, key)], key)
    assert out is not None
    assert not shown(out, password)
    assert out[1] == f'DB_PASSWORD = "{VALUE_MARK}"'


def test_a_password_inside_a_web_address_is_found() -> None:
    key, password = random_key(), random_text(20)
    lines = [f'DATABASE_URL = "postgres://app:{password}@db:5432/app"']
    out = redact_context(lines, 7, [target(7, password, key)], key)
    assert out is not None
    assert not shown(out, password)


def test_a_value_that_cannot_be_located_sends_nothing() -> None:
    key, token = random_key(), fake_acme_token()
    lines = [f'ACME_PAY_API_KEY = "{token}"']
    wrong_key = random_key()  # a report made somewhere else, with another fingerprint key
    assert redact_context(lines, 1, [target(1, token, wrong_key)], key) is None


def test_a_private_key_over_several_lines_sends_nothing() -> None:
    key, pem = random_key(), fake_private_key()
    lines = pem.splitlines()
    assert redact_context(lines, 1, [target(1, pem, key, "private-key")], key) is None


def test_our_own_semgrep_findings_point_at_code_and_their_line_is_kept() -> None:
    key = random_key()
    lines = ['log.info("Connecting to ACME Pay with %s", api_token)']
    finding = Target(1, "****", secrets.token_hex(32), "securegate-secret-logged")
    out = redact_context(lines, 1, [finding], key)
    assert out == [f'log.info("{STRING}", api_token)']


def test_every_string_literal_on_a_finding_line_is_replaced() -> None:
    key, token = random_key(), fake_acme_token()
    lines = [f'client = Client(key="{token}", region="eu-west", note=' + "'spare')"]
    out = redact_context(lines, 1, [target(1, token, key)], key)
    assert out == [f'client = Client(key="{VALUE_MARK}", region="{STRING}", note=' + f"'{STRING}')"]


def test_a_finding_outside_the_lines_changes_nothing() -> None:
    key, token = random_key(), fake_acme_token()
    lines = ["def charge(amount_cents: int) -> dict[str, object]:", "    return {}"]
    out = redact_context(lines, 1, [target(40, token, key)], key)
    assert out == lines


# --- the generic layer ------------------------------------------------------------------------


def test_key_shapes_and_random_tokens_are_taken_out_of_every_line() -> None:
    values = [
        fake_stripe_key(),
        fake_aws_key_id(),
        fake_github_token(),
        fake_acme_test_token(),
        random_text(32),
    ]
    lines = [f"# spare: {value} (do not use)" for value in values]
    out = [redact_text(line) for line in lines]
    assert not shown(out, *values)
    assert all(REDACTED in line for line in out)


def test_a_password_in_a_web_address_is_taken_out_by_the_generic_layer_too() -> None:
    password = random_text(10)
    out = redact_text(f"url = 'https://admin:{password}@example.com/path'")
    assert not shown([out], password)
    assert f"https://{REDACTED}@example.com/path" in out


def test_ordinary_code_is_kept_as_it_is() -> None:
    code = [
        "def charge(amount_cents: int) -> dict[str, object]:",
        '    ACME_PAY_API_KEY = os.environ["ACME_PAY_API_KEY"]',
        "    log = logging.getLogger(__name__)",
        "    return {'amount': amount_cents, 'currency': 'eur'}",
        "from securegate.demo.pull_requests import open_demo_pr",
    ]
    assert [redact_text(line) for line in code] == code


def test_policy_patterns_find_whole_tokens_anywhere_in_a_line() -> None:
    patterns = policy_patterns(load_policy(POLICY_FILE))
    token = fake_acme_test_token()
    out = redact_text(f"see the test key {token}, it is fine", patterns)
    assert not shown([out], token)
    assert out == f"see the test key {REDACTED}, it is fine"


def test_placeholder_patterns_are_not_used_for_redaction() -> None:
    patterns = policy_patterns(load_policy(POLICY_FILE))
    line = 'API_KEY = "YOUR_API_KEY_HERE"  # changeme'
    assert redact_text(line, patterns) == line


def test_inline_flags_stay_in_front() -> None:
    pattern = _unanchored("(?i)^acme_live_")
    token = fake_acme_token().upper()
    assert pattern.search(f"key={token}") is not None


# --- what comes back from an agent ------------------------------------------------------------


def test_clean_text_removes_markup_links_mentions_and_control_characters() -> None:
    raw = (
        "Rotate <b>now</b>: see [the docs](https://docs.example) or www.example.org, @someone"
        + chr(7)
    )
    assert clean_text(raw, 200) == "Rotate now: see the docs or (link removed), someone"


def test_clean_text_removes_tags_that_appear_when_another_is_removed() -> None:
    raw = "<<b>script>alert(1)<</b>/script>"
    cleaned = clean_text(raw, 200)
    assert "<script" not in cleaned
    assert "script>" not in cleaned


def test_clean_text_hides_anything_shaped_like_a_secret() -> None:
    token = fake_acme_token()
    cleaned = clean_text(f"The key {token} is live.", 200)
    assert not shown([cleaned], token)
    assert cleaned == "The key **** is live."


def test_clean_text_keeps_email_addresses_and_cuts_at_its_limit() -> None:
    assert clean_text("Tell security@example.com today.", 200) == "Tell security@example.com today."
    cleaned = clean_text("word " * 100, 40)
    assert len(cleaned) <= 40
    assert cleaned.endswith(chr(0x2026))


def test_clean_code_accepts_a_line_that_reads_the_environment() -> None:
    line = 'ACME_PAY_API_KEY = os.environ["ACME_PAY_API_KEY"]'
    assert clean_code(line, 300) == line


@pytest.mark.parametrize(
    "line",
    [
        f'ACME_PAY_API_KEY = "{VALUE_MARK}"',
        f'ACME_PAY_API_KEY = "{STRING}"',
        'URL = "https://example.com/hook"',
        "first line" + chr(10) + "second line",
        "caf" + chr(0xE9) + " = 1",
        "",
        "x" * 301,
    ],
)
def test_clean_code_refuses_lines_it_cannot_use_as_they_are(line: str) -> None:
    assert clean_code(line, 300) is None


def test_clean_code_refuses_a_line_with_a_key() -> None:
    line = f'ACME_PAY_API_KEY = os.environ.get("ACME_PAY_API_KEY", "{fake_acme_token()}")'
    assert clean_code(line, 300) is None


# --- the advice section of a report -----------------------------------------------------------

IDS = ["0123456789ab", "ba9876543210"]


def advice_data() -> dict[str, object]:
    return {
        "status": "ok",
        "note": None,
        "model": "gpt-5.4-mini",
        "made_at": "2026-10-07T10:00:00Z",
        "agents": {
            "triage": {"status": "ok", "note": None},
            "fix": {"status": "ok", "note": None},
            "incident": {"status": "skipped", "note": "Nothing was blocked."},
        },
        "triage": [
            {
                "finding": IDS[0],
                "verdict": "likely_real",
                "confidence": "high",
                "why": "A live ACME Pay token in application code.",
                "next_step": "Revoke it at ACME Pay, then read it from the environment.",
            }
        ],
        "fixes": [
            {
                "finding": IDS[0],
                "env_var": "ACME_PAY_API_KEY",
                "replacement": 'ACME_PAY_API_KEY = os.environ["ACME_PAY_API_KEY"]',
                "import_line": "import os",
                "why": "The code reads the key when it runs, so it is not in the repository.",
            }
        ],
        "incident": {
            "severity": "high",
            "exposure": "Public pull request, open for 2 hours.",
            "steps": [{"title": "Revoke the key", "detail": "In the ACME Pay dashboard."}],
            "notify": "The payments team.",
        },
    }


def test_valid_advice_is_read_and_written_back_the_same() -> None:
    advice = parse_advice(advice_data(), IDS)
    assert advice.triage_for(IDS[0]).verdict == "likely_real"
    assert advice.fix_for(IDS[0]).env_var == "ACME_PAY_API_KEY"
    assert advice.fix_for(IDS[1]) is None
    assert advice.incident.steps[0].title == "Revoke the key"
    assert parse_advice(advice.to_dict(), IDS) == advice


def _broken(path: tuple[object, ...], value: object) -> dict[str, object]:
    data = json.loads(json.dumps(advice_data()))
    place = data
    for step in path[:-1]:
        place = place[step]
    place[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("status",), "great"),
        (("triage", 0, "finding"), "ffffffffffff"),
        (("triage", 0, "verdict"), "definitely"),
        (("triage", 0, "why"), "x" * 401),
        (("triage", 0, "why"), "See https://evil.example/login now"),
        (("triage", 0, "why"), "Ask @someone about it"),
        (("triage", 0, "why"), "<script>alert(1)</script>"),
        (("fixes", 0, "env_var"), "acme key"),
        (("fixes", 0, "replacement"), "caf" + chr(0xE9) + " = 1"),
        (("incident", "severity"), "catastrophic"),
        (("incident", "steps"), []),
        (("agents",), {"oracle": {"status": "ok", "note": None}}),
        (("made_at",), "yesterday"),
    ],
)
def test_advice_that_breaks_a_rule_is_refused(path: tuple[object, ...], value: object) -> None:
    with pytest.raises(AdviceError):
        parse_advice(_broken(path, value), IDS)


def test_advice_holding_a_key_is_refused_and_the_error_does_not_quote_it() -> None:
    token = fake_acme_token()
    with pytest.raises(AdviceError) as refused:
        parse_advice(_broken(("triage", 0, "why"), f"The key is {token}"), IDS)
    assert not shown([str(refused.value)], token)
    assert has_secret(f"The key is {token}")


# --- advice in a report -----------------------------------------------------------------------


def _report_with(sample_report: Path, tmp_path: Path, advice: object) -> Path:
    data = json.loads(sample_report.read_text(encoding="utf-8"))
    ids = [f["id"] for f in data["findings"]]
    if isinstance(advice, dict):
        for item in advice.get("triage", []) + advice.get("fixes", []):
            item["finding"] = ids[0]
    data["advice"] = advice
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_report_with_advice_shows_it(sample_report: Path, tmp_path: Path) -> None:
    report = load_report(_report_with(sample_report, tmp_path, advice_data()))
    assert isinstance(report, ReportView)
    assert report.advice is not None
    assert report.advice_note is None
    assert report.advice.model == "gpt-5.4-mini"


def test_a_report_without_advice_reads_as_before(sample_report: Path, tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    shutil.copy(sample_report, path)
    report = load_report(path)
    assert isinstance(report, ReportView)
    assert (report.advice, report.advice_note) == (None, None)


def test_bad_advice_is_withheld_but_the_findings_are_still_shown(
    sample_report: Path, tmp_path: Path
) -> None:
    token = fake_acme_token()
    data = advice_data()
    data["triage"][0]["why"] = f"The key is {token}"
    report = load_report(_report_with(sample_report, tmp_path, data))
    assert isinstance(report, ReportView)
    assert report.advice is None
    assert report.advice_note == (
        "The AI advice in this report was withheld: it holds something shaped like a secret."
    )
    assert report.findings
    assert not shown([report.advice_note], token)


# --- every finding of the demo project --------------------------------------------------------


@pytest.mark.skipif(not git_installed(), reason="git is not installed")
def test_no_planted_value_survives_redaction_of_the_demo_project(demo_repo: DemoResult) -> None:
    """Each finding's lines, at its own commit, with every finding of that file and commit as a
    target: the values are located exactly, or nothing is sent."""
    key, policy = random_key(), load_policy(POLICY_FILE)
    result = run_scan(
        demo_repo.out,
        "repo",
        policy=policy,
        key=key,
        gitleaks_config=GITLEAKS_CONFIG,
        runner=FakeGitleaks(report=report_for_demo(demo_repo)),
    )
    patterns = policy_patterns(policy)
    sent, withheld = [], []
    for finding in result.findings:
        shown_file = subprocess.run(
            ["git", "-C", str(demo_repo.out), "show", f"{finding.commit}:{finding.file}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.splitlines()
        first = max(1, finding.line - 6)
        same = [
            Target(f.line, f.masked_value, f.fingerprint, f.rule)
            for f in result.findings
            if (f.file, f.commit) == (finding.file, finding.commit)
        ]
        lines = redact_context(shown_file[first - 1 : finding.line + 6], first, same, key, patterns)
        if lines is None:
            line = shown_file[finding.line - 1]
            multi_line = finding.rule == "private-key"
            withheld.append(multi_line or len(line) > MAX_SEARCH_LINE)
        else:
            sent.append("\n".join(lines))
    assert leaked(demo_repo.planted, "\n".join(sent)) == []
    assert all(withheld)  # only a value over several lines, or on an over-long line, is withheld
    assert len(sent) >= len(result.findings) - 2
