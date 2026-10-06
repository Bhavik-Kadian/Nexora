"""The five demo pull requests of `securegate demo-pr`: what each one commits, and what the merge
gate should say about it.

The files come from templates in pr_templates/. Every value that looks like a secret is made at
random when the pull request is built (see `fresh_values`), so none is stored in this repository.
"""

import secrets
import string
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

import jinja2

from securegate.demo.token import new_demo_token, new_test_token

NAMES = ("clean", "leak", "deleted-later", "decoys", "risky")
PASSWORD_LENGTH = 20


@dataclass(frozen=True, slots=True)
class Commit:
    message: str
    files: Mapping[str, str]  # path (with "/") -> content


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    title: str
    story: str  # what the pull request contains
    expected: str  # what the merge gate should say
    commits: tuple[Commit, ...]
    body: str  # the pull request description


@dataclass(frozen=True, slots=True)
class _Plan:
    title: str
    story: str
    expected: str
    commits: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]  # message, (path, template)


_PLANS = {
    "clean": _Plan(
        title="a harmless change",
        story="It adds a greeting for the checkout page, with no secret in it.",
        expected="green. Nothing to block.",
        commits=(("Add a checkout greeting", (("demo-app/greeting.py", "greeting.py.j2"),)),),
    ),
    "leak": _Plan(
        title="a payment key in the code",
        story="It writes a fake ACME Pay live token straight into `demo-app/payments.py`.",
        expected="red. Rule 8 (provider-keys) blocks the token, found by Gitleaks and TruffleHog.",
        commits=(
            ("Charge customers with ACME Pay", (("demo-app/payments.py", "payments_leak.py.j2"),)),
        ),
    ),
    "deleted-later": _Plan(
        title="a key deleted in a later commit",
        story=(
            "The first commit writes a fake ACME Pay live token into `demo-app/payments.py`; the "
            "second commit replaces it with `os.environ[...]`. The newest code is clean, but the "
            "first commit still holds the token, and anyone can open it."
        ),
        expected="still red. Rule 8 blocks the token, because the gate reads every commit.",
        commits=(
            ("Charge customers with ACME Pay", (("demo-app/payments.py", "payments_leak.py.j2"),)),
            (
                "Read the ACME Pay key from the environment",
                (("demo-app/payments.py", "payments_env.py.j2"),),
            ),
        ),
    ),
    "decoys": _Plan(
        title="decoys that look like secrets",
        story=(
            "It adds test data in `demo-app/tests/`: `YOUR_API_KEY_HERE`, `changeme`, an order "
            "number (a UUID) and a fake ACME Pay test-mode token."
        ),
        expected=(
            "green. Rule 3 (placeholders) ignores the placeholders and rule 7 "
            "(tests-fixtures-docs) only warns about the rest, and the comment explains each one."
        ),
        commits=(
            ("Add payments test data", (("demo-app/tests/test_payments.py", "test_decoys.py.j2"),)),
        ),
    ),
    "risky": _Plan(
        title="risky handling of secrets",
        story=(
            "It reads the ACME Pay token from the environment, then writes it to the log, and it "
            "puts a database password straight into the code."
        ),
        expected=(
            "green, with warnings: rule 13 (risky-handling, found by Semgrep) for the logged "
            "token and rule 10 (hardcoded-passwords, found by Bandit) for the password."
        ),
        commits=(("Connect to ACME Pay", (("demo-app/client.py", "client_risky.py.j2"),)),),
    ),
}


def fresh_values() -> dict[str, str]:
    """New random fake values for the templates."""
    alphabet = string.ascii_letters + string.digits
    return {
        "acme_live": new_demo_token(),
        "acme_test": new_test_token(),
        "password": "".join(secrets.choice(alphabet) for _ in range(PASSWORD_LENGTH)),
        "order_id": str(uuid.uuid4()),
    }


def build(name: str, values: Mapping[str, str]) -> Scenario:
    """The scenario called `name`, with `values` filled into its files."""
    plan = _PLANS.get(name)
    if plan is None:
        raise ValueError(f"unknown demo scenario: {name}")
    templates = _templates()
    commits = tuple(
        Commit(
            message=f"Demo: {message}",
            files={path: templates.get_template(name).render(values) for path, name in files},
        )
        for message, files in plan.commits
    )
    body = templates.get_template("pr_body.md.j2").render(
        name=name, story=plan.story, expected=plan.expected
    )
    return Scenario(
        name=name,
        title=plan.title,
        story=plan.story,
        expected=plan.expected,
        commits=commits,
        body=body,
    )


def _templates() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("securegate.demo", "pr_templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - Python and Markdown files, not HTML
    )
