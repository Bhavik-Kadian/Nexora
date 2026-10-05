"""The real Semgrep (our own rules only, so no internet is needed) and the real Bandit.

Sample code is written at runtime. Each sample line says which rule should fire on it, so the
test proves both that the rules catch risky code and that they leave the safe code alone.
Convention: raw test values never appear inside an assert.
"""

from pathlib import Path

import pytest

from helpers import SEMGREP_RULES, random_text
from securegate.mask import mask_value
from securegate.programs import find_program
from securegate.scanners import bandit, semgrep
from securegate.scanners.changes import Snapshot

LOGGED, URL, GETENV = (
    "securegate-secret-logged",
    "securegate-secret-in-url",
    "securegate-getenv-default",
)

# (code, the rule that must fire on it, or None for code that must stay quiet)
SAMPLE: list[tuple[str, str | None]] = [
    ("import logging", None),
    ("import os", None),
    ("import requests", None),
    ("log = logging.getLogger(__name__)", None),
    ("api_token = os.environ['API_TOKEN']", None),
    ("print(api_token)", LOGGED),
    ("log.info('using token %s', api_token)", LOGGED),
    ("logging.warning(f'key is {self.api_key}')", LOGGED),
    ("logger.debug('db password: {}'.format(db_password))", LOGGED),
    ("print(api_token)  # nosemgrep", LOGGED),  # a comment cannot hide it
    ("log.info('token refreshed')", None),
    ("print(get_token())", None),
    ("print(user_name)", None),
    ("url = f'https://api.example.com/v1/charges?token={api_token}'", URL),
    ("url = 'https://api.example.com/v1?api_key=' + api_token", URL),
    ("url = 'https://api.example.com/v1?secret=%s' % client_secret", URL),
    ("url = 'https://api.example.com/v1?token={}'.format(api_token)", URL),
    ("resp = requests.get('https://api.example.com', params={'key': api_token})", URL),
    ("path = f'https://api.example.com/v1/{api_token}'", None),
    ("url = f'https://api.example.com/v1?page={page}'", None),
    ("password = os.getenv('DB_PASSWORD', 'fallback')", GETENV),
    ("token = os.environ.get('ACME_PAY_API_KEY', 'dev-default')", GETENV),
    ("secret = os.getenv('CLIENT_SECRET', default='abc')", GETENV),
    ("level = os.getenv('LOG_LEVEL', 'INFO')", None),
    ("token = os.environ['ACME_PAY_API_KEY']", None),
    ("token = os.getenv('ACME_PAY_API_KEY')", None),
]


def copy_with(folder: Path, files: dict[str, str]) -> Snapshot:
    for name, text in files.items():
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(text, encoding="utf-8", newline="\n")
    (folder / ".semgrepignore").write_text("", encoding="utf-8")
    return Snapshot(folder, tuple(files))


@pytest.mark.skipif(not find_program("semgrep"), reason="semgrep is not installed (make scanners)")
def test_our_semgrep_rules_catch_risky_code_and_leave_safe_code_alone(tmp_path: Path) -> None:
    code = "\n".join(line for line, _ in SAMPLE) + "\n"
    snapshot = copy_with(tmp_path, {"app/risky.py": code, "tests/test_risky.py": code})

    output = semgrep.scan(
        snapshot, rules=SEMGREP_RULES, runner=semgrep.subprocess_runner(), registry=False
    )

    expected = {
        (rule, file, number)
        for file in ("app/risky.py", "tests/test_risky.py")  # tests/ is scanned too
        for number, (_, rule) in enumerate(SAMPLE, start=1)
        if rule
    }
    found = {(c.rule_id, c.file, c.line) for c in output.candidates}
    assert found == expected
    assert all(c.code for c in output.candidates)  # code, not secrets: shown as ****


@pytest.mark.skipif(not find_program("bandit"), reason="bandit is not installed (make scanners)")
def test_bandit_finds_hardcoded_passwords_even_with_nosec(tmp_path: Path) -> None:
    planted = ["Pw-" + random_text(16) for _ in range(4)]
    code = (
        f'password = "{planted[0]}"\n'
        f'connect(host="db", password="{planted[1]}")\n'
        f'def login(user, password="{planted[2]}"):\n'
        "    return user\n"
        f'db_password = "{planted[3]}"  # nosec\n'
        'user_name = "riya"\n'
    )
    snapshot = copy_with(tmp_path, {"app/db.py": code})

    output = bandit.scan(snapshot, runner=bandit.subprocess_runner())

    found = sorted((c.line, c.rule_id) for c in output.candidates)
    assert found == [(1, "bandit-B105"), (2, "bandit-B106"), (3, "bandit-B107"), (5, "bandit-B105")]
    masks = sorted(mask_value(c.value) for c in output.candidates)
    assert masks == sorted(mask_value(value) for value in planted)
    assert output.note is None
