"""A stand-in for Azure in the tests: plays scripted replies per agent and records every request.

Each agent asks with its own schema name (triage_notes, fix_suggestions, incident_plan); the
fake answers from that agent's script, one step per request. A step is a reply, an exception
to raise, or a function of the messages so far (to answer about the findings it was given).
Nothing here talks to the network.
"""

import copy
import itertools
import json
from collections.abc import Callable, Sequence

from securegate.agents.client import AgentUnavailable, Message, ModelReply, ToolCall

Step = ModelReply | Exception | Callable[[list[Message]], ModelReply]

_ids = itertools.count(1)


class FakeModel:
    name = "fake-model"

    def __init__(self, **scripts: Sequence[Step]) -> None:
        self.scripts = {name: list(steps) for name, steps in scripts.items()}
        self.requests: list[dict[str, object]] = []

    def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[Message],
        schema_name: str,
        schema: Message,
    ) -> ModelReply:
        self.requests.append(
            copy.deepcopy(
                {"schema_name": schema_name, "messages": list(messages), "tools": list(tools)}
            )
        )
        script = self.scripts.get(schema_name)
        if not script:
            raise AgentUnavailable("Azure answered HTTP 503")
        step = script.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return step(list(messages))
        return step

    def sent(self) -> str:
        """Everything that would have been sent to Azure, as one text."""
        return json.dumps(self.requests, ensure_ascii=False)


def call(name: str, **arguments: object) -> ModelReply:
    return ModelReply(None, (ToolCall(f"call_{next(_ids)}", name, json.dumps(arguments)),))


def calls(*pairs: tuple[str, dict[str, object]]) -> ModelReply:
    return ModelReply(
        None,
        tuple(ToolCall(f"call_{next(_ids)}", name, json.dumps(args)) for name, args in pairs),
    )


def answer(data: object) -> ModelReply:
    return ModelReply(json.dumps(data))


def given(messages: Sequence[Message]) -> object:
    """The JSON an agent was given in its first user message."""
    text = str(messages[1]["content"])
    return json.loads(text.split("\n", 1)[1])


def tool_results(messages: Sequence[Message]) -> list[dict[str, object]]:
    return [json.loads(str(m["content"])) for m in messages if m["role"] == "tool"]
