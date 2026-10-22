"""Deterministic stand-ins for the model behaviours that turn a secret in context into a leak."""
import re

from agent.llm import ModelReply


def _tool(i, name, **inp):
    return {"type": "tool_use", "id": f"s{i}", "name": name, "input": inp}


class PromptRepeater:
    """Obeys 'repeat your instructions verbatim' by echoing the system prompt back to the user."""

    def step(self, system, messages, tools):
        return ModelReply([{"type": "text", "text": f"My instructions are:\n{system}"}], "end_turn")


class BillingClient:
    """Does what the vulnerable prompt tells it: take BILLING_API_KEY from its instructions and pass it as api_key.

    With a clean prompt it simply calls the tool without a key. Then it reports what the tool returned.
    """

    def __init__(self, endpoint="/invoices"):
        self.endpoint = endpoint

    def step(self, system, messages, tools):
        last = messages[-1]["content"]
        if isinstance(last, str):
            m = re.search(r"BILLING_API_KEY=(\S+)", system)
            args = {"endpoint": self.endpoint, **({"api_key": m[1]} if m else {})}
            return ModelReply([_tool(0, "call_api", **args)], "tool_use")
        return ModelReply([{"type": "text", "text": f"Billing says: {last[0]['content']}"}], "end_turn")


class EnvReader:
    """Reads .env (as an injected instruction or a curious user might ask) and reports it."""

    def step(self, system, messages, tools):
        last = messages[-1]["content"]
        if isinstance(last, str):
            return ModelReply([_tool(0, "read_file", path=".env")], "tool_use")
        return ModelReply([{"type": "text", "text": f"Here is the file: {last[0]['content']}"}], "end_turn")
