"""One agent's run: the model looks with its tools, then answers in the agreed JSON shape.

The loop is bounded: at most MAX_TOOL_CALLS tool calls and MAX_MODEL_CALLS model calls. An
answer that cannot be used is asked for once more, then the agent fails. A failed agent never
stops SecureGate: its advice says it did not answer, and the policy's decisions stand.
"""

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from securegate.agents.client import AgentUnavailable, Message, Model
from securegate.agents.tools import ToolBox

MAX_TOOL_CALLS = 6
MAX_MODEL_CALLS = 8

RETRY = (
    "That answer could not be used: it did not match what was asked. Answer again with JSON "
    "that matches the schema exactly, using only the finding ids you were given."
)
NO_MORE_TOOLS = json.dumps({"error": "No more tool calls are allowed: answer now."})
NOT_YOURS = json.dumps({"error": "That tool is not available to you."})


class Unusable(ValueError):
    """An agent's answer had the right shape but nothing in it could be used."""


@dataclass(frozen=True)
class Outcome[T]:
    status: str  # ok, skipped or failed
    result: T | None = None
    note: str | None = None


def run_agent[T](
    model: Model,
    *,
    system: str,
    user: str,
    toolbox: ToolBox,
    tools: Sequence[str],
    schema_name: str,
    schema: Message,
    accept: Callable[[object], T],
) -> Outcome[T]:
    """Run one agent to its answer. `accept` turns the answer into checked results, or raises
    ValueError when it cannot be used."""
    messages: list[Message] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    specs = toolbox.specs(tools)
    tool_calls = 0
    retried = False
    for _ in range(MAX_MODEL_CALLS):
        try:
            reply = model.complete(messages, specs, schema_name, schema)
        except AgentUnavailable as err:
            return Outcome("failed", note=str(err))
        if reply.tool_calls:
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {"name": call.name, "arguments": call.arguments},
                        }
                        for call in reply.tool_calls
                    ],
                }
            )
            for call in reply.tool_calls:
                tool_calls += 1
                if tool_calls > MAX_TOOL_CALLS:
                    content = NO_MORE_TOOLS
                elif call.name not in tools:
                    content = NOT_YOURS
                else:
                    content = toolbox.call(call.name, call.arguments)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
            continue
        try:
            return Outcome("ok", result=accept(json.loads(reply.content or "")))
        except ValueError:
            if retried:
                return Outcome("failed", note="the model's answer could not be used")
            retried = True
            messages.append({"role": "assistant", "content": reply.content or ""})
            messages.append({"role": "user", "content": RETRY})
    return Outcome("failed", note="the agent did not finish within its limit of steps")
