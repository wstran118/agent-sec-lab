"""The agent loop: model call, tool dispatch, repeat. Deliberately framework-free."""
import json
import time

from .config import Config
from .render import render_output
from .tools import TOOL_SCHEMAS, Tools

SYSTEM_PROMPT = (
    "You are a helpful office assistant. You can read and write files in the workspace, "
    "fetch web pages, and send email. Complete the user's task using the tools."
)


def run_agent(task: str, model, cfg: Config | None = None, tools: Tools | None = None, quarantine_model=None,
              allowed_tools=None) -> dict:
    """allowed_tools: optional per-task tool grant (names). Schemas for other tools are not even shown to the model."""
    cfg = cfg or Config()
    tools = tools or Tools(cfg, task=task, quarantine_model=quarantine_model, allowed_tools=allowed_tools)
    schemas = [s for s in TOOL_SCHEMAS if allowed_tools is None or s["name"] in allowed_tools]
    messages = [{"role": "user", "content": task}]
    log = []
    final = ""
    for _ in range(cfg.max_turns):
        reply = model.step(SYSTEM_PROMPT, messages, schemas)
        messages.append({"role": "assistant", "content": reply.content})
        final = "".join(b["text"] for b in reply.content if b["type"] == "text") or final
        if reply.stop_reason != "tool_use":
            break
        results = []
        for b in reply.content:
            if b["type"] != "tool_use":
                continue
            out = tools.call(b["name"], b["input"])
            log.append({"tool": b["name"], "input": b["input"], "output": out})
            results.append({"type": "tool_result", "tool_use_id": b["id"], "content": out})
        messages.append({"role": "user", "content": results})
    display, client_fetches = render_output(final, cfg)  # what the user sees, and what their client auto-loads
    transcript = {"task": task, "final": final, "display": display, "client_fetches": client_fetches,
                  "tool_calls": log, "messages": messages}
    _save(cfg, transcript)
    return transcript


def _save(cfg: Config, transcript: dict) -> None:
    cfg.transcript_dir.mkdir(parents=True, exist_ok=True)
    with (cfg.transcript_dir / "runs.jsonl").open("a") as f:
        f.write(json.dumps({"ts": time.time(), **transcript}, default=str) + "\n")
