"""`securegate ai-setup`: tell SecureGate where the AI agents' model lives in Azure.

It asks for the resource's endpoint, the model deployment's name and the key, checks each one,
and writes .securegate/ai.json (Git ignores that folder). The key is typed hidden and is never
shown again. A wrong answer is asked for again, up to three times; then nothing is saved.
"""

from collections.abc import Callable, Mapping
from pathlib import Path

from securegate.agents.settings import (
    DEFAULT_DEPLOYMENT,
    DEPLOYMENT_VAR,
    ENDPOINT_VAR,
    KEY_VAR,
    AiSettings,
    check_deployment,
    check_endpoint,
    save_settings,
)
from securegate.errors import ConfigError

ATTEMPTS = 3
MIN_KEY_LENGTH = 16


def run_setup(
    *,
    ask: Callable[[str], str],
    ask_secret: Callable[[str], str],
    say: Callable[[str], None],
    state_dir: Path,
    env: Mapping[str, str],
) -> AiSettings:
    """Ask, check and save the settings. `ask_secret` must not show what is typed."""
    say(
        "The AI agents use a model you deploy in Azure AI Foundry. docs/agents.md shows where "
        "to find these three values."
    )
    endpoint = _ask_until(
        ask, "Endpoint (such as https://my-resource.openai.azure.com): ", check_endpoint, say
    )
    deployment = _ask_until(
        ask,
        f"Model deployment name (Enter for {DEFAULT_DEPLOYMENT}): ",
        lambda answer: check_deployment(answer or DEFAULT_DEPLOYMENT),
        say,
    )
    key = _ask_until(
        ask_secret, "Key (it stays hidden while you type or paste it): ", _check_key, say
    )
    settings = AiSettings(endpoint, deployment, key)
    path = save_settings(state_dir, settings)
    say(f"Saved in {path}. Git ignores that folder; never share the file.")
    if any(env.get(name) for name in (ENDPOINT_VAR, DEPLOYMENT_VAR, KEY_VAR)):
        say("Note: SECUREGATE_AI_ environment variables are set, and they come before this file.")
    return settings


def _ask_until(
    ask: Callable[[str], str],
    prompt: str,
    check: Callable[[str], str],
    say: Callable[[str], None],
) -> str:
    for _ in range(ATTEMPTS):
        try:
            return check(ask(prompt).strip())
        except ConfigError as err:
            say(str(err))
    raise ConfigError("ai-setup stopped after three answers it could not use; nothing was saved")


def _check_key(value: str) -> str:
    if len(value) < MIN_KEY_LENGTH or any(c.isspace() or not c.isprintable() for c in value):
        raise ConfigError(
            "That does not look like an Azure key: copy KEY 1 from the resource's Keys and "
            "Endpoint page, and paste it."
        )
    return value
