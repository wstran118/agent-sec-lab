"""Model backends. Messages use the Anthropic content-block dict format for both backends."""
from dataclasses import dataclass


@dataclass
class ModelReply:
    content: list[dict]  # blocks: {"type":"text","text":..} / {"type":"tool_use","id","name","input"}
    stop_reason: str  # "tool_use" or "end_turn"


class AnthropicModel:
    def __init__(self, model: str, max_tokens: int):
        import anthropic  # lazy: mock mode needs no SDK or key

        self.client = anthropic.Anthropic()  # key from ANTHROPIC_API_KEY only
        self.model, self.max_tokens = model, max_tokens

    def step(self, system: str, messages: list[dict], tools: list[dict]) -> ModelReply:
        r = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system, tools=tools, messages=messages
        )
        blocks = []
        for b in r.content:
            if b.type == "text":
                blocks.append({"type": "text", "text": b.text})
            elif b.type == "tool_use":
                blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
        return ModelReply(blocks, r.stop_reason)


class MockModel:
    """Scripted model for deterministic tests and CI. Each script item is a block list or a callable(messages)."""

    def __init__(self, script):
        self.script, self.i = script, 0

    def step(self, system, messages, tools) -> ModelReply:
        item = self.script[self.i]
        self.i += 1
        blocks = item(messages) if callable(item) else item
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
        return ModelReply(blocks, stop)
