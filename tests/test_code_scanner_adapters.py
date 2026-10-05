"""The Semgrep and Bandit adapters, with scripted fakes (no programs needed).

Convention: raw test values never appear inside an assert; masks, counts and booleans do.
"""

from pathlib import Path

import pytest

from fake_code_scanners import FakeBandit, FakeSemgrep, Spot
from helpers import SEMGREP_RULES, fake_stripe_key, random_text
from securegate.errors import ScannerError
from securegate.mask import mask_value
from securegate.scanners import bandit, semgrep
from securegate.scanners.changes import Snapshot

REGISTRY_ID = "generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key"


def snapshot_with(folder: Path, files: dict[str, str]) -> Snapshot:
    for name, text in files.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return Snapshot(folder, tuple(files))


# --- Semgrep -------------------------------------------------------------------------------------


def test_semgrep_runs_both_rule_sets_with_the_safety_flags() -> None:
    args = semgrep.build_command(["p/secrets", "ours.yml"])
    assert args[:5] == ["scan", "--config", "p/secrets", "--config", "ours.yml"]
    for flag in ("--json", "--disable-version-check", "--disable-nosem", "--no-git-ignore",
                 "--no-rewrite-rule-ids"):  # fmt: skip
        assert flag in args
    assert args[args.index("--metrics") + 1] == "off"
    assert args[-3:] == ["--project-root", ".", "."]


def test_semgrep_results_become_candidates_cut_from_our_copy(tmp_path: Path) -> None:
    key = fake_stripe_key()
    snapshot = snapshot_with(
        tmp_path,
        {"app/pay.py": f'import os\nSTRIPE = "{key}"\n', "app/log.py": "print(api_token)\n"},
    )
    fake = FakeSemgrep(
        spots=[
            Spot(REGISTRY_ID, "app/pay.py", key),
            Spot("securegate-secret-logged", "app/log.py", "print(api_token)"),
        ]
    )

    output = semgrep.scan(snapshot, rules=SEMGREP_RULES, runner=fake)

    stripe, logged = output.candidates
    assert (output.version, output.note) == ("1.179.0", None)
    assert (stripe.rule_id, stripe.file, stripe.line, stripe.code) == (
        "detected-stripe-api-key",
        "app/pay.py",
        2,
        False,
    )
    assert mask_value(stripe.value) == mask_value(key)
    assert (logged.rule_id, logged.file, logged.code) == (
        "securegate-secret-logged",
        "app/log.py",
        True,
    )
    assert (stripe.detector, stripe.commit, stripe.validity) == ("semgrep", None, "not_checked")


def test_quotes_around_a_secret_are_not_part_of_it(tmp_path: Path) -> None:
    key = fake_stripe_key()
    snapshot = snapshot_with(tmp_path, {"a.py": f'X = "{key}"\n'})
    fake = FakeSemgrep(spots=[Spot(REGISTRY_ID, "a.py", f'"{key}"')])
    (found,) = semgrep.scan(snapshot, rules=SEMGREP_RULES, runner=fake).candidates
    assert mask_value(found.value) == mask_value(key)


def test_without_internet_semgrep_runs_our_rules_alone_and_says_so(tmp_path: Path) -> None:
    snapshot = snapshot_with(tmp_path, {"a.py": "print(api_token)\n"})
    fake = FakeSemgrep(
        spots=[Spot("securegate-secret-logged", "a.py", "print(api_token)")],
        registry_offline=True,
    )

    output = semgrep.scan(snapshot, rules=SEMGREP_RULES, runner=fake)

    first, second = fake.scans
    assert fake.configs(first) == ["p/secrets", str(SEMGREP_RULES.resolve())]
    assert fake.configs(second) == [str(SEMGREP_RULES.resolve())]
    assert output.note == semgrep.OFFLINE_NOTE
    assert len(output.candidates) == 1


def test_files_semgrep_could_not_read_are_counted(tmp_path: Path) -> None:
    snapshot = snapshot_with(tmp_path, {"a.py": "x = 1\n"})
    output = semgrep.scan(snapshot, rules=SEMGREP_RULES, runner=FakeSemgrep(errors=2))
    assert output.note == "it could not read 2 files"


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (FakeSemgrep(exit_code=2), r"it failed \(exit code 2\)"),
        (FakeSemgrep(missing=True), "not installed"),
        (FakeSemgrep(help_without=("--disable-nosem",)), "lacks --disable-nosem"),
    ],
)
def test_semgrep_failures_are_scanner_errors(
    tmp_path: Path, fake: FakeSemgrep, message: str
) -> None:
    snapshot = snapshot_with(tmp_path, {"a.py": "x = 1\n"})
    with pytest.raises(ScannerError, match=message):
        semgrep.scan(snapshot, rules=SEMGREP_RULES, runner=fake)


def test_a_missing_rules_file_is_a_scanner_error(tmp_path: Path) -> None:
    snapshot = snapshot_with(tmp_path, {"a.py": "x = 1\n"})
    with pytest.raises(ScannerError, match=r"rules file .* was not found"):
        semgrep.scan(snapshot, rules=tmp_path / "missing.yml", runner=FakeSemgrep())


def test_a_result_outside_the_copy_is_refused(tmp_path: Path) -> None:
    snapshot = snapshot_with(tmp_path / "copy", {"a.py": "x = 1\n"})
    data = {
        "results": [
            {
                "check_id": "x",
                "path": "../outside.py",
                "start": {"line": 1, "offset": 0},
                "end": {"line": 1, "offset": 1},
            }
        ]
    }
    (tmp_path / "outside.py").write_text("y = 2\n", encoding="utf-8")
    with pytest.raises(ScannerError, match="points outside the scanned files"):
        semgrep.parse_results(data, snapshot)


# --- Bandit --------------------------------------------------------------------------------------


def test_bandit_runs_the_password_checks_with_the_safety_flags() -> None:
    args = bandit.build_command(["a.py"])
    assert args == [
        "-f", "json", "-q", "-t", "B105,B106,B107", "--ignore-nosec", "--exit-zero", "a.py",
    ]  # fmt: skip


def test_bandit_takes_the_password_from_its_message_only(tmp_path: Path) -> None:
    password = "Pw-" + random_text(16)
    snapshot = snapshot_with(
        tmp_path, {"app/db.py": f'password = "{password}"\n', "notes.txt": "x"}
    )
    fake = FakeBandit(spots=[Spot("B105", "app/db.py", password)])

    output = bandit.scan(snapshot, runner=fake)

    (found,) = output.candidates
    (scan,) = fake.scans
    assert scan[-1:] == ["app/db.py"]  # only Python files are given to Bandit
    assert (found.rule_id, found.file, found.line, found.code) == (
        "bandit-B105",
        "app/db.py",
        1,
        False,
    )
    assert mask_value(found.value) == mask_value(password)
    assert (output.version, output.note) == ("1.9.4", None)


def test_no_python_files_means_no_bandit_run(tmp_path: Path) -> None:
    fake = FakeBandit()
    output = bandit.scan(snapshot_with(tmp_path, {"README.md": "# hi\n"}), runner=fake)
    assert (fake.scans, output.candidates) == ([], [])


def test_files_bandit_could_not_read_are_counted(tmp_path: Path) -> None:
    snapshot = snapshot_with(tmp_path, {"a.py": "x = 1\n"})
    output = bandit.scan(snapshot, runner=FakeBandit(unreadable=["a.py"]))
    assert output.note == "it could not read 1 file"


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (FakeBandit(exit_code=2), r"it failed \(exit code 2\)"),
        (FakeBandit(garbled=True), "not JSON"),
        (FakeBandit(missing=True), "not installed"),
    ],
)
def test_bandit_failures_are_scanner_errors(tmp_path: Path, fake: FakeBandit, message: str) -> None:
    with pytest.raises(ScannerError, match=message):
        bandit.scan(snapshot_with(tmp_path, {"a.py": "x = 1\n"}), runner=fake)


def test_a_bandit_result_without_a_password_shows_none_of_its_place() -> None:
    data = {
        "results": [
            {
                "test_id": "B106",
                "filename": "a.py",
                "line_number": 3,
                "issue_text": "Possible hardcoded password: ''",
            }
        ]
    }
    (found,) = bandit.parse_results(data)
    assert (found.code, found.line) == (True, 3)
