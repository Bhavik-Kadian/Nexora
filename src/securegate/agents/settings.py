"""Where the AI agents find Azure: the endpoint, the model deployment and the key.

Environment variables come first (the merge gate sets them from GitHub's secrets and variables),
then .securegate/ai.json, which `securegate ai-setup` writes on a laptop (Git ignores the
.securegate folder). The key is only ever sent to an Azure address over HTTPS, and it is never
printed: AiSettings hides it from repr.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from securegate.errors import ConfigError

ENDPOINT_VAR = "SECUREGATE_AI_ENDPOINT"
DEPLOYMENT_VAR = "SECUREGATE_AI_DEPLOYMENT"
KEY_VAR = "SECUREGATE_AI_KEY"
DEFAULT_DEPLOYMENT = "gpt-5.4-mini"
SETTINGS_FILE = "ai.json"
AZURE_HOSTS = (".openai.azure.com", ".cognitiveservices.azure.com", ".services.ai.azure.com")


@dataclass(frozen=True)
class AiSettings:
    endpoint: str  # https://<resource>.openai.azure.com, without a path
    deployment: str  # the model deployment's name in Azure AI Foundry
    key: str = field(repr=False)


def load_settings(env: Mapping[str, str], state_dir: Path) -> AiSettings | None:
    """The settings, or None when the AI agents are not set up (no endpoint or no key)."""
    stored = _stored(state_dir / SETTINGS_FILE)
    endpoint = env.get(ENDPOINT_VAR) or stored.get("endpoint") or ""
    key = env.get(KEY_VAR) or stored.get("key") or ""
    deployment = env.get(DEPLOYMENT_VAR) or stored.get("deployment") or DEFAULT_DEPLOYMENT
    if not endpoint.strip() or not key.strip():
        return None
    return AiSettings(check_endpoint(endpoint), check_deployment(deployment), key.strip())


def check_endpoint(endpoint: str) -> str:
    """The endpoint as https://host, or ConfigError when it is not an Azure address."""
    parts = urlsplit(endpoint.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(AZURE_HOSTS) or parts.username:
        raise ConfigError(
            f"{ENDPOINT_VAR} must be the HTTPS address of an Azure AI Foundry resource, such as "
            "https://my-resource.openai.azure.com"
        )
    return f"https://{host}" + (f":{parts.port}" if parts.port else "")


def check_deployment(deployment: str) -> str:
    name = deployment.strip()
    if not name or len(name) > 64 or not all(c.isalnum() or c in "-_." for c in name):
        raise ConfigError(f"{DEPLOYMENT_VAR} must be a deployment name, such as gpt-5.4-mini")
    return name


def save_settings(state_dir: Path, settings: AiSettings) -> Path:
    """Write .securegate/ai.json for this laptop. The folder is the one Git ignores."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / SETTINGS_FILE
    data = {"endpoint": settings.endpoint, "deployment": settings.deployment, "key": settings.key}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)  # only on systems with file modes; Windows ignores it
    return path


def _stored(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise ConfigError(f"{path} is not readable: run `securegate ai-setup` again") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path} is not readable: run `securegate ai-setup` again")
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
