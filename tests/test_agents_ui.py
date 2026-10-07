"""Layer 3, M3: the AI advice in the PR comment, the dashboard, ai-setup and ai-check.

Advice here is written by hand into a copy of the sample report; no model is involved except a
fake one for the connection check. No test reaches Azure.
"""

import json
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from fake_model import FakeModel, answer
from helpers import Page, fake_acme_token
from securegate.agents.client import AgentUnavailable
from securegate.agents.settings import AiSettings, load_settings
from securegate.agents.setup import run_setup
from securegate.doctor import ai_checks
from securegate.errors import ConfigError
from securegate.outputs import markdown
from securegate.outputs.markdown import code_block, render_comment, render_summary
from securegate.ui.app import create_app
from securegate.ui.report_view import ReportView, load_report

ENDPOINT = "https://securegate-demo.openai.azure.com"


def advice_for(data: dict) -> dict:
    """Advice about the first blocked and the first warned finding of a report."""
    block = next(
        f for f in data["findings"] if f["decision"] == "block" and f["file"].endswith(".py")
    )
    warn = next(f for f in data["findings"] if f["decision"] == "warn")
    return {
        "status": "ok",
        "note": None,
        "model": "gpt-5.4-mini",
        "made_at": "2026-10-07T12:00:00Z",
        "agents": {
            "triage": {"status": "ok", "note": None},
            "fix": {"status": "ok", "note": None},
            "incident": {"status": "ok", "note": None},
        },
        "triage": [
            {
                "finding": block["id"],
                "verdict": "likely_real",
                "confidence": "high",
                "why": "A live key in application code.",
                "next_step": "Revoke it at the provider.",
            },
            {
                "finding": warn["id"],
                "verdict": "likely_false_alarm",
                "confidence": "medium",
                "why": "It looks like a commit hash.",
                "next_step": "Nothing to do.",
            },
        ],
        "fixes": [
            {
                "finding": block["id"],
                "env_var": "STRIPE_SECRET_KEY",
                "replacement": 'STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]',
                "import_line": "import os",
                "why": "The code reads the key when it runs.",
            }
        ],
        "incident": {
            "severity": "high",
            "exposure": "The key has been in the history since June.",
            "steps": [
                {"title": "Revoke the key", "detail": "In the provider's dashboard."},
                {"title": "Check the logs", "detail": "Look for use since the commit date."},
            ],
            "notify": "The payments team.",
        },
    }


@pytest.fixture
def advised(sample_report: Path, tmp_path: Path) -> Path:
    """A copy of the sample report, with AI advice in it."""
    data = json.loads(sample_report.read_text(encoding="utf-8"))
    data["advice"] = advice_for(data)
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def with_advice(path: Path, advice: object) -> Path:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["advice"] = advice
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def loaded(path: Path) -> ReportView:
    report = load_report(path)
    assert isinstance(report, ReportView)
    return report


# --- the pull request comment and the job summary ---------------------------------------------


def test_the_comment_has_an_ai_section_after_the_findings(advised: Path) -> None:
    comment = render_comment(loaded(advised))
    section = comment.split("#### AI advice: the policy decided, not the AI", 1)
    assert len(section) == 2
    text = section[1]
    assert "Advice from gpt-5.4-mini" in text
    assert "likely real, high confidence. A live key in application code." in text
    assert "likely a false alarm, medium confidence." in text
    assert "read `STRIPE_SECRET_KEY` from the environment (it needs `import os`)" in text
    assert '```python\nSTRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]\n```' in text
    assert "<summary>Incident plan: high</summary>" in text
    assert "1. **Revoke the key**: In the provider's dashboard." in text
    assert "Who to tell: The payments team." in text


def test_the_summary_has_the_same_section(advised: Path) -> None:
    assert "#### AI advice" in render_summary(loaded(advised))


def test_a_report_without_advice_has_no_ai_section(sample_report: Path) -> None:
    assert "AI advice" not in render_comment(loaded(sample_report))


def test_withheld_advice_says_so(advised: Path) -> None:
    data = json.loads(advised.read_text(encoding="utf-8"))
    data["advice"]["triage"][0]["why"] = f"The key is {fake_acme_token()}"
    advised.write_text(json.dumps(data), encoding="utf-8")
    comment = render_comment(loaded(advised))
    assert (
        "The AI advice in this report was withheld: it holds something shaped like a secret."
        in comment
    )
    assert "Triage" not in comment


def test_advice_that_was_not_asked_for_says_why(sample_report: Path, tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_bytes(sample_report.read_bytes())
    skipped = {"status": "skipped", "note": "The AI agents are not set up where this scan ran."}
    comment = render_comment(loaded(with_advice(path, skipped)))
    assert "The AI agents are not set up where this scan ran." in comment


def test_agents_that_did_not_answer_are_named(sample_report: Path, tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_bytes(sample_report.read_bytes())
    failed = {
        "status": "failed",
        "agents": {"triage": {"status": "failed", "note": "Azure answered HTTP 503"}},
    }
    comment = render_comment(loaded(with_advice(path, failed)))
    assert "The AI agents did not answer" in comment
    assert "The triage agent did not answer: Azure answered HTTP 503." in comment


def test_advice_too_long_for_a_comment_is_left_out(
    advised: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(markdown, "MAX_LENGTH", 500)
    comment = render_comment(loaded(advised))
    assert "The AI advice is too long for this comment." in comment
    assert "Triage" not in comment


def test_a_code_line_cannot_close_its_code_block() -> None:
    block = code_block("x = `a` + ```b```", "app.js")
    fence = block.split("\n", 1)[0]
    assert fence == "````javascript"
    assert block.endswith("\n````")


# --- the dashboard ------------------------------------------------------------------------------


@pytest.fixture
def advised_client(advised: Path) -> FlaskClient:
    return create_app(advised).test_client()


def test_a_finding_page_shows_the_ai_triage_and_fix(
    advised_client: FlaskClient, advised: Path
) -> None:
    advice = json.loads(advised.read_text(encoding="utf-8"))["advice"]
    page = advised_client.get(f"/findings/{advice['fixes'][0]['finding']}").get_data(as_text=True)
    assert "AI triage" in page
    assert "Likely real" in page
    assert "AI fix suggestion" in page
    assert "STRIPE_SECRET_KEY = os.environ[&#34;STRIPE_SECRET_KEY&#34;]" in page


def test_a_finding_without_advice_has_no_ai_panels(sample_report: Path) -> None:
    client = create_app(sample_report).test_client()
    first = json.loads(sample_report.read_text(encoding="utf-8"))["findings"][0]["id"]
    page = client.get(f"/findings/{first}").get_data(as_text=True)
    assert "AI triage" not in page


def test_the_advice_page_shows_the_plan_the_triage_and_the_fixes(
    advised_client: FlaskClient,
) -> None:
    response = advised_client.get("/advice")
    text = Page(response.get_data(as_text=True)).text
    assert response.status_code == 200
    assert "Incident plan" in text
    assert (
        "Revoke the key : In the provider's dashboard." in text
        or "Revoke the key: In the provider" in text
    )
    assert "likely a false alarm, medium confidence" in text
    assert "Suggested fixes" in text


def test_the_advice_page_says_when_nobody_asked(sample_report: Path) -> None:
    text = create_app(sample_report).test_client().get("/advice").get_data(as_text=True)
    assert "No advice yet" in text
    assert "securegate agents --report" in text


def test_the_overview_says_what_the_agents_gave(advised_client: FlaskClient) -> None:
    text = Page(advised_client.get("/").get_data(as_text=True)).text
    assert "AI advice 2 triage notes, 1 fix, an incident plan" in text


def test_the_json_download_keeps_the_advice_only_with_every_finding(
    advised_client: FlaskClient, tmp_path: Path
) -> None:
    whole = json.loads(advised_client.get("/export/findings.json").get_data(as_text=True))
    part = json.loads(
        advised_client.get("/export/findings.json?decision=block").get_data(as_text=True)
    )
    assert "advice" in whole
    assert "advice" not in part
    again = tmp_path / "again.json"
    again.write_text(json.dumps(whole), encoding="utf-8")
    assert loaded(again).advice is not None  # the download opens again, advice included


# --- ai-setup ---------------------------------------------------------------------------------


class Answers:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


def test_setup_asks_checks_and_saves(tmp_path: Path) -> None:
    key = "k" * 40
    said: list[str] = []
    ask = Answers("http://not-azure.example", ENDPOINT, "")
    settings = run_setup(
        ask=ask, ask_secret=Answers("short", key), say=said.append, state_dir=tmp_path, env={}
    )
    assert settings == AiSettings(ENDPOINT, "gpt-5.4-mini", key)
    assert load_settings({}, tmp_path) == settings
    shown = any(key in line for line in said)
    assert not shown
    assert any("HTTPS address of an Azure AI Foundry resource" in line for line in said)
    assert any("does not look like an Azure key" in line for line in said)


def test_setup_gives_up_after_three_unusable_answers(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="nothing was saved"):
        run_setup(
            ask=Answers("a", "b", "c"),
            ask_secret=Answers(),
            say=lambda _line: None,
            state_dir=tmp_path,
            env={},
        )
    assert load_settings({}, tmp_path) is None


def test_setup_without_a_keyboard_fails_closed(run_cli, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", Answers())
    result = run_cli("ai-setup")
    assert result.exit_code == 2
    assert "ai-setup needs someone at the keyboard" in result.err


# --- ai-check and doctor ------------------------------------------------------------------------


def test_ai_check_skips_when_not_set_up() -> None:
    (check,) = ai_checks(lambda: None)
    assert (check.status, check.name) == ("SKIP", "AI agents")


def test_ai_check_passes_when_the_model_answers() -> None:
    model = FakeModel(connection_check=[answer({"ok": True})])
    checks = ai_checks(lambda: model)
    assert [(c.status, c.name) for c in checks] == [
        ("PASS", "AI settings"),
        ("PASS", "AI connection"),
    ]
    request = json.dumps(model.requests)
    assert "SecureGate connection check." in request
    assert "findings" not in request


@pytest.mark.parametrize(
    ("step", "detail"),
    [
        (AgentUnavailable("Azure refused the key (HTTP 401)"), "Azure refused the key (HTTP 401)"),
        (answer({"ok": False}), "the model answered, but not as asked"),
    ],
)
def test_ai_check_fails_when_the_model_does_not_answer_as_asked(step, detail: str) -> None:
    model = FakeModel(connection_check=[step])
    assert ai_checks(lambda: model)[-1].line() == f"FAIL  AI connection: {detail}"


def test_ai_check_fails_on_broken_settings() -> None:
    def broken() -> None:
        raise ConfigError("SECUREGATE_AI_ENDPOINT must be the HTTPS address of an Azure resource")

    (check,) = ai_checks(broken)
    assert check.status == "FAIL"


def test_the_ai_check_command_exits_1_when_the_connection_fails(run_cli) -> None:
    result = run_cli("ai-check", model_factory=lambda: FakeModel())
    assert result.exit_code == 1
    assert "FAIL  AI connection: Azure answered HTTP 503" in result.out
