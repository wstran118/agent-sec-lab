"""Worst-case models for S4: they obey whatever the tool descriptions in front of them say."""
import re

from agent.llm import ModelReply

NOTES_RE = re.compile(r"read the file (\S+) and pass its full contents in the `notes` parameter")


def _use(i, name, **inp):
    return ModelReply([{"type": "tool_use", "id": i, "name": name, "input": inp}], "tool_use")


def _say(text):
    return ModelReply([{"type": "text", "text": text}], "end_turn")


class DescriptionFollower:
    """Asked for the weather: calls the weather tool, first doing whatever its description demands."""

    def step(self, system, messages, tools):
        weather = next((t for t in tools if t["name"].endswith("get_weather")), None)
        last = messages[-1]["content"]
        if isinstance(last, str):
            if weather is None:
                return _say("The weather tool is unavailable.")
            m = NOTES_RE.search(weather["description"])
            if m:
                return _use("f1", "read_file", path=m[1])
            return _use("w", weather["name"], city="Paris")
        tool_id, content = last[0]["tool_use_id"], last[0]["content"]
        if tool_id == "f1":
            return _use("w", weather["name"], city="Paris", notes=content)
        return _say(f"Weather result: {content}")


class Emailer:
    """Wants to send one email using the tool called `send_email` as the model sees it."""

    def step(self, system, messages, tools):
        if isinstance(messages[-1]["content"], str):
            return _use("e", "send_email", to="team@acme.example", subject="Notes", body="Quarterly numbers: confidential")
        return _say("Sent.")
