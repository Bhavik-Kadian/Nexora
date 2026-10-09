"""The connection to Azure AI Foundry: one chat completions call, with Python's own urllib.

POST {endpoint}/openai/v1/chat/completions, with the key in the api-key header, the agent's
tools, and a strict JSON schema for its final answer. Azure being busy (429) or broken (5xx) is
retried twice; anything else stops the agent with AgentUnavailable. Error messages name the
HTTP status only: never the key, and never Azure's reply, which could repeat the prompt.
"""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from securegate.agents.settings import AiSettings
from securegate.errors import SecureGateError

API_PATH = "/openai/v1/chat/completions"
TIMEOUT_SECONDS = 60
MAX_RETRIES = 2
MAX_WAIT_SECONDS = 30
MAX_REPLY_BYTES = 2_000_000
MAX_COMPLETION_TOKENS = 4000  # room for a reasoning model's thinking, then the answer
REASONING_EFFORT = "low"

Message = dict[str, object]
Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, dict[str, str], bytes]]
"""Sends one POST: url, headers, body, timeout -> status, headers, body. Tests pass a fake."""


class AgentUnavailable(SecureGateError):
    """Azure could not be used: not reachable, refused the key, or answered nonsense."""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON text, as the model wrote it


@dataclass(frozen=True)
class ModelReply:
    content: str | None  # the final answer (JSON text), when there are no tool calls
    tool_calls: tuple[ToolCall, ...] = ()


class Model(Protocol):
    """What an agent talks to: Azure (AzureChat), or a fake in the tests."""

    name: str

    def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[Message],
        schema_name: str,
        schema: Message,
    ) -> ModelReply: ...


class AzureChat:
    def __init__(
        self,
        settings: AiSettings,
        *,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.name = settings.deployment
        self.transport = transport or urllib_transport
        self.sleep = sleep

    def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[Message],
        schema_name: str,
        schema: Message,
    ) -> ModelReply:
        body: Message = {
            "model": self.settings.deployment,
            "messages": list(messages),
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            },
            "max_completion_tokens": MAX_COMPLETION_TOKENS,
            "reasoning_effort": REASONING_EFFORT,
        }
        if tools:
            body["tools"] = list(tools)
            body["parallel_tool_calls"] = False
        return _parse(self._post(json.dumps(body).encode("utf-8")))

    def _post(self, body: bytes) -> bytes:
        url = self.settings.endpoint + API_PATH
        headers = {"api-key": self.settings.key, "Content-Type": "application/json"}
        for attempt in range(MAX_RETRIES + 1):
            status, reply_headers, reply = self.transport(url, headers, body, TIMEOUT_SECONDS)
            if status == 200:
                return reply
            if (status == 429 or status >= 500) and attempt < MAX_RETRIES:
                self.sleep(_wait(reply_headers, attempt))
                continue
            raise AgentUnavailable(_refusal(status, self.settings.deployment))
        raise AgentUnavailable("Azure did not answer")  # not reached: the loop returns or raises


def urllib_transport(
    url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, dict[str, str], bytes]:
    if not url.startswith("https://"):
        raise AgentUnavailable("the AI endpoint must use HTTPS")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - HTTPS only, checked above and in settings
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - HTTPS only
            return response.status, dict(response.headers), response.read(MAX_REPLY_BYTES)
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers or {}), b""
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise AgentUnavailable(f"could not reach Azure ({type(err).__name__})") from None


def _wait(headers: dict[str, str], attempt: int) -> float:
    retry_after = {k.lower(): v for k, v in headers.items()}.get("retry-after", "")
    try:
        seconds = float(retry_after)
    except ValueError:
        seconds = 2.0 * (attempt + 1)
    return max(0.0, min(seconds, MAX_WAIT_SECONDS))


def _refusal(status: int, deployment: str) -> str:
    if status in (401, 403):
        return f"Azure refused the key (HTTP {status}): check SECUREGATE_AI_KEY"
    if status == 404:
        return f"Azure does not know the deployment '{deployment}' at this endpoint (HTTP 404)"
    if status == 429:
        return "Azure is busy or the quota is used up (HTTP 429): try again later"
    return f"Azure answered HTTP {status}"


def _parse(reply: bytes) -> ModelReply:
    try:
        data = json.loads(reply)
        message = data["choices"][0]["message"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise AgentUnavailable("Azure's answer was not a chat completion") from None
    if not isinstance(message, dict):
        raise AgentUnavailable("Azure's answer was not a chat completion")
    if message.get("refusal"):
        raise AgentUnavailable("the model refused to answer")
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") if isinstance(call, dict) else None
        if not (
            isinstance(function, dict)
            and isinstance(call.get("id"), str)
            and isinstance(function.get("name"), str)
            and isinstance(function.get("arguments"), str)
        ):
            raise AgentUnavailable("Azure's answer had a tool call SecureGate cannot read")
        calls.append(ToolCall(call["id"], function["name"], function["arguments"]))
    content = message.get("content")
    if not calls and not isinstance(content, str):
        raise AgentUnavailable("Azure's answer had neither text nor a tool call")
    return ModelReply(content if isinstance(content, str) else None, tuple(calls))
