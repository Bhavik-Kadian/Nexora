"""The policy engine: default rules, first match wins, conditions, globs and validation.

Convention: raw test values never appear inside an assert.
"""

import re
from collections.abc import Callable
from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from helpers import (
    fake_acme_test_token,
    fake_acme_token,
    fake_aws_key_id,
    fake_github_token,
    fake_private_key,
    fake_stripe_key,
    random_text,
)
from securegate.errors import ConfigError, SecureGateError
from securegate.finding import Validity
from securegate.policy import (
    Conditions,
    Policy,
    PolicyRule,
    Verdict,
    decide,
    glob_to_regex,
    load_policy,
    parse_policy,
)

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "policy.yaml"

# Live-mode key formats, built at runtime. Rule 8 looks at the value itself, so it does not
# matter which scanner rule reported it.
LIVE_KEYS: dict[str, Callable[[], str]] = {
    "acme-live": fake_acme_token,
    "stripe-secret": fake_stripe_key,
    "stripe-restricted": lambda: fake_stripe_key(kind="rk"),
    "aws-akia": fake_aws_key_id,
    "aws-asia": lambda: fake_aws_key_id("ASIA"),
    "bedrock-long-lived": lambda: "ABSK" + random_text(40),
    "bedrock-short-lived": lambda: "bedrock-" + "api-key-" + random_text(40),
    "github-pat": fake_github_token,
    "github-oauth": lambda: fake_github_token("gho"),
    "github-app": lambda: fake_github_token("ghs"),
    "github-fine-grained": lambda: "github_" + "pat_" + random_text(60),
    "private-key": fake_private_key,
}
TEST_MODE_KEYS: dict[str, Callable[[], str]] = {
    "acme-test": fake_acme_test_token,
    "stripe-test": lambda: fake_stripe_key("test"),
    "stripe-restricted-test": lambda: fake_stripe_key("test", kind="rk"),
}
SHIPPED_RULES = [
    (1, "verified-live"),
    (3, "placeholders"),
    (7, "tests-fixtures-docs"),
    (8, "provider-keys"),
    (9, "test-mode-keys"),
    (10, "hardcoded-passwords"),
    (13, "risky-handling"),
    (14, "everything-else"),
]


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(DEFAULT_POLICY)


def verdict_for(
    policy: Policy,
    *,
    rule_id: str = "generic-api-key",
    path: str = "app/config.py",
    value: str | None = None,
    entropy: float = 4.5,
    validity: Validity = "not_checked",
) -> Verdict:
    return decide(
        policy,
        rule_id=rule_id,
        path=path,
        value=random_text(32) if value is None else value,
        entropy=entropy,
        validity=validity,
    )


def outcome(verdict: Verdict) -> tuple[str, str, str]:
    return verdict.rule_name, verdict.decision, verdict.severity


def policy_from(text: str) -> Policy:
    return parse_policy(yaml.safe_load(dedent(text)), source="test-policy.yaml")


# --- the shipped default policy --------------------------------------------------------------


def test_shipped_policy_loads_with_numbered_rules_in_order(policy: Policy) -> None:
    assert [(rule.number, rule.name) for rule in policy.rules] == SHIPPED_RULES


@pytest.mark.parametrize("path", ["app/payments.py", "tests/test_pay.py", "docs/keys.md"])
def test_rule_1_a_key_confirmed_live_blocks_as_critical_anywhere(policy: Policy, path: str) -> None:
    verdict = verdict_for(policy, rule_id="trufflehog-stripe", path=path, validity="verified")
    assert outcome(verdict) == ("verified-live", "block", "critical")
    assert verdict.label == "rule 1: verified-live"


@pytest.mark.parametrize("validity", ["unknown", "unverified", "not_checked"])
def test_rule_1_needs_a_confirmed_live_key(policy: Policy, validity: str) -> None:
    verdict = verdict_for(policy, rule_id="trufflehog-stripe", validity=validity)
    assert verdict.rule_name != "verified-live"


PLACEHOLDERS: dict[str, Callable[[], str]] = {
    "your-here": lambda: "YOUR_" + "STRIPE_SECRET_KEY" + "_HERE",
    "changeme": lambda: "changeme",
    "changeme-inside": lambda: "db-" + "CHANGEME" + "-" + random_text(6),
    "example": lambda: random_text(13) + "EXAMPLE",
    "xxxx": lambda: "x" * 8,
    "XXXX-after-prefix": lambda: "sk_live_" + "X" * 24,
    "dummy": lambda: "dummy-" + random_text(10),
}


@pytest.mark.parametrize("make_value", PLACEHOLDERS.values(), ids=PLACEHOLDERS.keys())
def test_placeholders_are_ignored_even_under_provider_rules(
    policy: Policy, make_value: Callable[[], str]
) -> None:
    verdict = verdict_for(policy, rule_id="stripe-access-token", value=make_value())
    assert outcome(verdict) == ("placeholders", "ignore", "info")


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_app.py",
        "services/api/tests/unit/test_x.py",
        "fixtures/data.json",
        "tests/fixtures/stripe.json",
        "docs/setup.md",
        "a/b/docs/c.md",
    ],
)
def test_tests_fixtures_and_docs_paths_warn(policy: Policy, path: str) -> None:
    verdict = verdict_for(policy, rule_id="aws-access-token", path=path, value=fake_aws_key_id())
    assert outcome(verdict) == ("tests-fixtures-docs", "warn", "medium")


@pytest.mark.parametrize("path", ["README.md", "documentation.md", ".env.example", "a/b.example"])
def test_markdown_and_example_files_warn_like_docs(policy: Policy, path: str) -> None:
    verdict = verdict_for(policy, rule_id="stripe-access-token", path=path, value=fake_stripe_key())
    assert outcome(verdict) == ("tests-fixtures-docs", "warn", "medium")


@pytest.mark.parametrize(
    "path", ["contests/entry.py", "src/testsuite.py", "docs.py", "app/example.py", "md/a.py"]
)
def test_lookalike_paths_are_not_treated_as_tests_or_docs(policy: Policy, path: str) -> None:
    verdict = verdict_for(policy, rule_id="aws-access-token", path=path, value=fake_aws_key_id())
    assert verdict.rule_name == "provider-keys"


@pytest.mark.parametrize("make_value", LIVE_KEYS.values(), ids=LIVE_KEYS.keys())
@pytest.mark.parametrize("rule_id", ["generic-api-key", "trufflehog-stripe", "bandit-B105"])
def test_rule_8_live_key_formats_block_as_high(
    policy: Policy, make_value: Callable[[], str], rule_id: str
) -> None:
    verdict = verdict_for(policy, rule_id=rule_id, value=make_value())
    assert outcome(verdict) == ("provider-keys", "block", "high")
    assert verdict.label == "rule 8: provider-keys"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(lambda: "ASIAN" + random_text(20), id="aws-prefix-in-a-word"),
        pytest.param(lambda: "x_" + fake_stripe_key(), id="stripe-not-at-start"),
        pytest.param(lambda: "ghx_" + random_text(36), id="unknown-github-prefix"),
    ],
)
def test_rule_8_needs_the_format_at_the_start(policy: Policy, value: Callable[[], str]) -> None:
    verdict = verdict_for(policy, rule_id="trufflehog-unknown", value=value())
    assert verdict.rule_name != "provider-keys"


@pytest.mark.parametrize("make_value", TEST_MODE_KEYS.values(), ids=TEST_MODE_KEYS.keys())
def test_rule_9_test_mode_keys_warn(policy: Policy, make_value: Callable[[], str]) -> None:
    verdict = verdict_for(policy, rule_id="stripe-access-token", value=make_value())
    assert outcome(verdict) == ("test-mode-keys", "warn", "medium")


@pytest.mark.parametrize(
    "rule_id", ["bandit-B105", "bandit-B106", "bandit-B107", "generic-api-key"]
)
def test_rule_10_hardcoded_passwords_warn(policy: Policy, rule_id: str) -> None:
    verdict = verdict_for(policy, rule_id=rule_id)
    assert outcome(verdict) == ("hardcoded-passwords", "warn", "medium")


@pytest.mark.parametrize(
    "rule_id",
    ["securegate-secret-logged", "securegate-secret-in-url", "securegate-getenv-default"],
)
def test_rule_13_risky_handling_warns_low(policy: Policy, rule_id: str) -> None:
    verdict = verdict_for(policy, rule_id=rule_id)
    assert outcome(verdict) == ("risky-handling", "warn", "low")


@pytest.mark.parametrize("rule_id", ["slack-bot-token", "jwt", "trufflehog-slack"])
def test_rule_14_everything_else_warns(policy: Policy, rule_id: str) -> None:
    verdict = verdict_for(policy, rule_id=rule_id)
    assert outcome(verdict) == ("everything-else", "warn", "medium")
    assert verdict.label == "rule 14: everything-else"


def test_first_match_wins_placeholder_in_tests_is_ignored(policy: Policy) -> None:
    verdict = verdict_for(
        policy, rule_id="aws-access-token", path="tests/test_aws.py", value="x" * 20
    )
    assert outcome(verdict) == ("placeholders", "ignore", "info")


def test_first_match_wins_provider_key_in_docs_only_warns(policy: Policy) -> None:
    verdict = verdict_for(
        policy, rule_id="aws-access-token", path="docs/aws-setup.md", value=fake_aws_key_id()
    )
    assert outcome(verdict) == ("tests-fixtures-docs", "warn", "medium")


def test_first_match_wins_test_mode_key_in_tests_is_a_tests_warning(policy: Policy) -> None:
    verdict = verdict_for(policy, path="demo-app/tests/test_pay.py", value=fake_acme_test_token())
    assert outcome(verdict) == ("tests-fixtures-docs", "warn", "medium")


def test_verdict_names_the_rule_and_says_what_to_do(policy: Policy) -> None:
    verdict = verdict_for(policy, rule_id="stripe-access-token", value=fake_stripe_key())
    assert verdict.reason.startswith("provider-keys: ")
    assert "Rotate" in verdict.remediation


def test_verdict_never_contains_the_value(policy: Policy) -> None:
    value = random_text(40)
    verdict = verdict_for(policy, value=value)
    value_visible = value in repr(verdict)
    assert not value_visible


# --- conditions ------------------------------------------------------------------------------

CATCH_ALL = """
  - name: rest
    decision: warn
    severity: medium
"""


def test_min_entropy_matches_at_or_above_the_number() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: random-looking
            when: {min_entropy: 4.0}
            decision: block
            severity: high
          - name: rest
            decision: warn
            severity: medium
        """
    )
    names = [verdict_for(policy, entropy=e).rule_name for e in (4.5, 4.0, 3.9)]
    assert names == ["random-looking", "random-looking", "rest"]


def test_all_conditions_under_when_must_match() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: aws-in-config
            when:
              rule_ids: [aws-access-token]
              path_matches: ['config/**']
            decision: block
            severity: critical
          - name: rest
            decision: warn
            severity: medium
        """
    )
    both = verdict_for(policy, rule_id="aws-access-token", path="config/app.yaml")
    only_rule = verdict_for(policy, rule_id="aws-access-token", path="app/main.py")
    only_path = verdict_for(policy, rule_id="generic-api-key", path="config/app.yaml")
    assert [both.rule_name, only_rule.rule_name, only_path.rule_name] == [
        "aws-in-config",
        "rest",
        "rest",
    ]


def test_one_matching_entry_in_a_list_is_enough() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: either
            when:
              value_matches: ['^alpha', 'omega$']
            decision: ignore
            severity: info
          - name: rest
            decision: warn
            severity: medium
        """
    )
    names = [
        verdict_for(policy, value=v).rule_name
        for v in ("alpha-" + random_text(8), random_text(8) + "-omega", random_text(12))
    ]
    assert names == ["either", "either", "rest"]


def test_a_single_text_is_accepted_instead_of_a_list() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: aws
            when: {rule_ids: aws-access-token}
            decision: block
            severity: critical
          - name: rest
            decision: warn
            severity: medium
        """
    )
    assert verdict_for(policy, rule_id="aws-access-token").rule_name == "aws"


def test_missing_reason_gets_a_default_naming_the_rule() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: rest
            decision: warn
            severity: medium
        """
    )
    assert verdict_for(policy).reason == "rest: matched policy rule 'rest'"


def test_decide_fails_closed_when_no_rule_matches() -> None:
    only_aws = PolicyRule(
        name="aws-only",
        conditions=Conditions(rule_ids=frozenset({"aws-access-token"})),
        decision="block",
        severity="critical",
        reason="",
        remediation="",
    )
    broken = Policy(rules=(only_aws,), source="built-in-test")
    with pytest.raises(ConfigError, match="no rule matched"):
        verdict_for(broken, rule_id="generic-api-key")


# --- path globs ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**/tests/**", "tests/a.py", True),
        ("**/tests/**", "x/y/tests/b.py", True),
        ("**/tests/**", "contests/c.py", False),
        ("**/tests/**", "tests", False),
        ("docs/**", "docs/a/b.md", True),
        ("docs/**", "src/docs/a.md", False),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("**/*.md", "docs/README.md", True),
        ("**/*.md", "README.md", True),
        ("config/?.yaml", "config/a.yaml", True),
        ("config/?.yaml", "config/ab.yaml", False),
        ("a.b", "axb", False),
        ("**", "any/path/at/all.txt", True),
    ],
)
def test_glob_semantics(pattern: str, path: str, expected: bool) -> None:
    assert (glob_to_regex(pattern).fullmatch(path) is not None) is expected


# --- validation ------------------------------------------------------------------------------

INVALID_POLICIES = [
    pytest.param("version: 1\nrules: [\n", "is not valid YAML", id="bad-yaml"),
    pytest.param("", "expected 'version: 1'", id="empty-file"),
    pytest.param("just some text", "expected 'version: 1'", id="not-a-mapping"),
    pytest.param("version: 2\nrules:" + CATCH_ALL, "'version' must be 1", id="wrong-version"),
    pytest.param("version: 1\nrules: []", "at least one rule", id="no-rules"),
    pytest.param("version: 1\nrule:" + CATCH_ALL, "did you mean 'rules'", id="unknown-top-key"),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    decison: warn\n    severity: low",
        "did you mean 'decision'",
        id="unknown-rule-key",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {path_match: ['a/**']}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "did you mean 'path_matches'",
        id="unknown-condition-key",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {value_matches: ['(unclosed']}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "not a valid regular expression",
        id="bad-regex",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    decision: allow\n    severity: low",
        "'decision' must be one of: block, warn, ignore",
        id="bad-decision",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    decision: warn\n    severity: urgent",
        "'severity' must be one of",
        id="bad-severity",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {rule_ids: [jwt]}\n"
        "    decision: warn\n    severity: low",
        "must have no 'when'",
        id="no-catch-all",
    ),
    pytest.param(
        "version: 1\nrules:" + CATCH_ALL + "  - name: later\n    when: {rule_ids: [jwt]}\n"
        "    decision: block\n    severity: high\n  - name: last\n"
        "    decision: warn\n    severity: medium",
        "can never be used",
        id="catch-all-not-last",
    ),
    pytest.param("version: 1\nrules:" + CATCH_ALL + CATCH_ALL, "must be unique", id="duplicate"),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {}\n    decision: warn\n    severity: low",
        "'when' must list at least one of",
        id="empty-when",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {min_entropy: high}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "'min_entropy' must be a number",
        id="min-entropy-text",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {min_entropy: true}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "'min_entropy' must be a number",
        id="min-entropy-bool",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {min_entropy: -1}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "'min_entropy' must be a number",
        id="min-entropy-negative",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {path_matches: ['tests\\\\**']}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "must use '/'",
        id="glob-backslash",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {path_matches: ['/docs/**']}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "no leading '/'",
        id="glob-leading-slash",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {rule_ids: []}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "must be a list of non-empty texts",
        id="empty-list",
    ),
    pytest.param(
        "version: 1\nrules:\n  - just a sentence", "must have name, decision", id="rule-not-map"
    ),
    pytest.param(
        "version: 1\nrules:\n  - decision: warn\n    severity: low",
        "'name' must be a non-empty text",
        id="missing-name",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    decision: warn\n    severity: low\n    reason: 42",
        "'reason' must be text",
        id="reason-not-text",
    ),
    pytest.param(
        "version: 1\nrules:\n  - number: eight\n    name: x\n    decision: warn\n    severity: low",
        "'number' must be a whole number",
        id="number-text",
    ),
    pytest.param(
        "version: 1\nrules:\n  - number: 0\n    name: x\n    decision: warn\n    severity: low",
        "'number' must be a whole number",
        id="number-zero",
    ),
    pytest.param(
        "version: 1\nrules:\n  - number: true\n    name: x\n    decision: warn\n    severity: low",
        "'number' must be a whole number",
        id="number-bool",
    ),
    pytest.param(
        "version: 1\nrules:\n  - number: 3\n    name: x\n    when: {rule_ids: [jwt]}\n"
        "    decision: warn\n    severity: low" + CATCH_ALL,
        "either every rule has a 'number' or none does; missing on: rest",
        id="number-missing-on-one-rule",
    ),
    pytest.param(
        "version: 1\nrules:\n  - number: 8\n    name: x\n    when: {rule_ids: [jwt]}\n"
        "    decision: warn\n    severity: low\n  - number: 3\n    name: rest\n"
        "    decision: warn\n    severity: medium",
        "rule numbers must go up from top to bottom",
        id="numbers-going-down",
    ),
    pytest.param(
        "version: 1\nrules:\n  - name: x\n    when: {validity: [verifed]}\n"
        "    decision: block\n    severity: critical" + CATCH_ALL,
        "validity 'verifed' is unknown (did you mean 'verified'?)",
        id="unknown-validity",
    ),
]


def test_numbered_rules_are_labelled_and_may_skip_numbers() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - number: 3
            name: jwt
            when: {rule_ids: [jwt]}
            decision: warn
            severity: low
          - number: 14
            name: rest
            decision: warn
            severity: medium
        """
    )
    labels = [verdict_for(policy, rule_id=r).label for r in ("jwt", "generic-api-key")]
    assert labels == ["rule 3: jwt", "rule 14: rest"]


def test_errors_point_at_a_rule_by_its_table_number_or_its_place() -> None:
    unnumbered = "version: 1\nrules:\n  - name: x\n    decision: stop\n    severity: low"
    numbered = unnumbered.replace("  - name: x", "  - number: 10\n    name: x")
    with pytest.raises(ConfigError, match=re.escape("rule 10 ('x'): 'decision' must be one of")):
        policy_from(numbered)
    with pytest.raises(ConfigError, match=re.escape("rule #1 ('x'): 'decision' must be one of")):
        policy_from(unnumbered)


def test_unnumbered_rules_are_labelled_by_name() -> None:
    policy = policy_from("version: 1\nrules:" + CATCH_ALL)
    assert verdict_for(policy).label == "rest"


def test_validity_condition_matches_only_the_listed_results() -> None:
    policy = policy_from(
        """
        version: 1
        rules:
          - name: live
            when: {validity: [verified, unknown]}
            decision: block
            severity: critical
          - name: rest
            decision: warn
            severity: medium
        """
    )
    validities: tuple[Validity, ...] = ("verified", "unknown", "unverified", "not_checked")
    names = [verdict_for(policy, validity=v).rule_name for v in validities]
    assert names == ["live", "live", "rest", "rest"]


@pytest.mark.parametrize(("text", "message"), INVALID_POLICIES)
def test_invalid_policies_are_refused_with_a_clear_message(
    tmp_path: Path, text: str, message: str
) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_policy(policy_file)


def test_missing_policy_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="policy file not found"):
        load_policy(tmp_path / "nope.yaml")


def test_policy_errors_mean_exit_code_2() -> None:
    # The CLI turns every SecureGateError into exit code 2 (checked end to end in test_cli.py).
    assert issubclass(ConfigError, SecureGateError)
