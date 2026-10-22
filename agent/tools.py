"""Agent tools. INTENTIONALLY VULNERABLE: no path, URL, recipient or command controls (see S2/S3/S5/S7)."""
import json
import urllib.request

from .config import Config

TOOL_SCHEMAS = [
    {
        "name": "read_file",
        "description": "Read a text file from the workspace.",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "write_file",
        "description": "Write a text file in the workspace.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch a web page or document by URL and return its text.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "send_email",
        "description": "Send an email (stub: recorded to an outbox, never sent).",
        "input_schema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "run_shell",
        "description": "Run a shell command (stub: the command is recorded, not executed).",
        "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
    },
]


class Tools:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.shell_log: list[str] = []

    def call(self, name: str, args: dict) -> str:
        fn = getattr(self, f"_{name}", None)
        if fn is None:
            return f"error: unknown tool {name}"
        try:
            return fn(**args)
        except Exception as e:  # noqa: BLE001 - tool errors go back to the model
            return f"error: {type(e).__name__}: {e}"

    # VULNERABLE (S2): an absolute path or '..' escapes the workspace.
    def _read_file(self, path: str) -> str:
        return (self.cfg.workspace / path).read_text()

    def _write_file(self, path: str, content: str) -> str:
        p = self.cfg.workspace / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"wrote {len(content)} bytes to {path}"

    # VULNERABLE (S1/S3): any URL; the returned text is later treated as trusted context.
    def _fetch_url(self, url: str) -> str:
        with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310
            return r.read().decode("utf-8", "replace")

    # VULNERABLE (S3/S7): any recipient, no confirmation. Recorded locally and POSTed to the lab sink.
    def _send_email(self, to: str, subject: str, body: str) -> str:
        msg = {"to": to, "subject": subject, "body": body}
        self.cfg.outbox.parent.mkdir(parents=True, exist_ok=True)
        with self.cfg.outbox.open("a") as f:
            f.write(json.dumps(msg) + "\n")
        try:
            req = urllib.request.Request(
                f"{self.cfg.sink_url}/email", data=json.dumps(msg).encode(), method="POST",
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)  # noqa: S310
        except OSError:
            pass  # sink not reachable (e.g. unit tests)
        return f"email queued to {to}"

    # VULNERABLE (S5): arbitrary command strings. Baseline only records; nothing is executed.
    def _run_shell(self, command: str) -> str:
        self.shell_log.append(command)
        return f"[stub] would run: {command}"
