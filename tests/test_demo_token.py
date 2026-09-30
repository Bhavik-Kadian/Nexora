"""`securegate demo-token`: fresh fake ACME Pay tokens that the gates block.

Convention: the tokens never appear inside an assert.
"""

import re
from pathlib import Path

import pytest

from helpers import POLICY_FILE, gitleaks_installed, scan_args
from securegate.cli import main
from securegate.entropy import shannon_entropy
from securegate.policy import decide, load_policy

ACME_FORMAT = re.compile(r"acme_(live|test)_[A-Za-z0-9]{32}")


def demo_token(capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    exit_code = main(["demo-token"])
    return exit_code, capsys.readouterr().out


def test_prints_one_token_in_the_acme_format(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code, printed = demo_token(capsys)
    one_line = printed.endswith("\n") and printed.count("\n") == 1
    acme_format = ACME_FORMAT.fullmatch(printed.strip()) is not None
    assert exit_code == 0
    assert one_line
    assert acme_format


def test_every_run_gives_a_new_token(capsys: pytest.CaptureFixture[str]) -> None:
    tokens = {demo_token(capsys)[1] for _ in range(5)}
    assert len(tokens) == 5


def test_the_policy_blocks_a_demo_token(capsys: pytest.CaptureFixture[str]) -> None:
    token = demo_token(capsys)[1].strip()
    verdict = decide(
        load_policy(POLICY_FILE),
        rule_id="acme-pay-token",
        path="demo_leak.py",
        value=token,
        entropy=shannon_entropy(token),
    )
    assert (verdict.rule_name, verdict.decision) == ("provider-keys", "block")


@pytest.mark.skipif(not gitleaks_installed(), reason="gitleaks is not installed")
def test_gitleaks_finds_a_demo_token_with_our_acme_rule(
    run_cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    token = demo_token(capsys)[1].strip()
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "demo_leak.py").write_text(f"ACME_PAY_API_KEY = '{token}'\n", encoding="utf-8")

    result = run_cli(*scan_args(folder, mode="dir"))

    assert result.exit_code == 1
    assert [(f["rule"], f["file"], f["decision"]) for f in result.findings] == [
        ("acme-pay-token", "demo_leak.py", "block")
    ]
    token_visible = token in result.out + result.err
    assert not token_visible
