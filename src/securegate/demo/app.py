"""The fake "DemoPay" payments app that every demo repo is built from.

BASE_FILES are the app's own files (rendered from templates/). Files that only the catalog
mentions are built from a generic template for their file type. STORY is the commit history:
each file is added once and never edited, so ground-truth line numbers stay valid.
"""

from dataclasses import dataclass

APP_NAME = "DemoPay"
AUTHOR_NAME = "Riya Demo"
AUTHOR_EMAIL = "riya@example.com"


@dataclass(frozen=True)
class AppFile:
    template: str
    plantable: bool = True  # the template has a marker line where planted lines can go


BASE_FILES: dict[str, AppFile] = {
    "README.md": AppFile("readme.md.j2"),
    ".gitignore": AppFile("gitignore.j2", plantable=False),
    "requirements.txt": AppFile("requirements.txt.j2", plantable=False),
    "app/__init__.py": AppFile("app_init.py.j2", plantable=False),
    "app/main.py": AppFile("app_main.py.j2"),
    "config/settings.py": AppFile("config_settings.py.j2"),
    "config/app.yaml": AppFile("config_app.yaml.j2"),
    ".env.example": AppFile("env_example.j2"),
    "docker-compose.yml": AppFile("docker_compose.yml.j2"),
    "payments/__init__.py": AppFile("payments_init.py.j2", plantable=False),
    "payments/stripe_client.py": AppFile("payments_stripe_client.py.j2"),
    "web/checkout.js": AppFile("web_checkout.js.j2"),
    "package.json": AppFile("package.json.j2"),
    "package-lock.json": AppFile("package_lock.json.j2"),
    "Dockerfile": AppFile("dockerfile.j2"),
    "tests/test_payments.py": AppFile("tests_test_payments.py.j2"),
    "docs/payments.md": AppFile("docs_payments.md.j2"),
}

# Template for a file only the catalog mentions, by file type (see fakes.file_type).
GENERIC_TEMPLATES = {
    "python": "generic_python.j2",
    "yaml": "generic_yaml.j2",
    "js": "generic_js.j2",
    "json": "generic_json.j2",
    "env": "generic_env.j2",
    "dockerfile": "generic_dockerfile.j2",
    "markdown": "generic_markdown.j2",
    "shell": "generic_shell.j2",
    "raw": "generic_raw.j2",
}


@dataclass(frozen=True)
class Step:
    """One commit of the story."""

    message: str
    files: tuple[str, ...] = ()  # app files added in this commit
    folders: tuple[str, ...] = ()  # catalog-only files in these top folders ("" = repo root)
    history: str | None = None  # "add" or "remove" the history-only files
    rest: bool = False  # catalog-only files that no earlier step took


STORY = (
    Step(
        "Start the DemoPay payments service",
        files=("README.md", ".gitignore", "requirements.txt", "app/__init__.py", "app/main.py"),
        folders=("app",),
    ),
    Step(
        "Add configuration",
        files=("config/settings.py", "config/app.yaml", ".env.example", "docker-compose.yml"),
        folders=("", "config"),
    ),
    Step("Add one-off maintenance scripts", history="add"),
    Step(
        "Add Stripe payments client",
        files=("payments/__init__.py", "payments/stripe_client.py"),
        folders=("payments",),
    ),
    Step(
        "Add checkout page",
        files=("web/checkout.js", "package.json", "package-lock.json"),
        folders=("web",),
    ),
    Step("Add Docker build", files=("Dockerfile",), folders=("deploy",)),
    Step("Remove one-off maintenance scripts", history="remove"),
    Step(
        "Add tests and docs",
        files=("tests/test_payments.py", "docs/payments.md"),
        folders=("tests", "docs"),
    ),
    Step("Add supporting files", rest=True),
)
