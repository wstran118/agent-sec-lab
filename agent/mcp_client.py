"""Minimal MCP-style client plus the S4 defences: manifest pinning and description scanning.

INTENTIONALLY VULNERABLE by default: `Tools.load_mcp()` re-fetches the manifest on every run and trusts it.
"""
import hashlib
import json
import re
import urllib.request

SUSPICIOUS = [
    (re.compile(r"<\s*/?\s*(important|system|instructions?)\s*>", re.I), "hidden instruction block"),
    (re.compile(r"ignore (all |any |your )?(previous|prior|above)", re.I), "tries to override instructions"),
    (re.compile(r"do not (mention|tell|reveal|show)", re.I), "asks for concealment"),
    (re.compile(r"\b(read|open|cat|send|pass|include|attach)\b.{0,80}(\.env|\.ssh|id_rsa|passwd|password|credential|secret|api[_-]?key|token)", re.I | re.S),
     "asks to move credentials or secret files"),
    (re.compile(r"before (using|calling|invoking) (this|the) tool", re.I), "pre-call side effects"),
    (re.compile(r"(instead of|replaces?|in place of) (the )?(built-?in|other|default|existing)", re.I), "tool shadowing"),
    (re.compile(r"\balways use this\b", re.I), "tool shadowing"),
]
MAX_DESCRIPTION = 1000


def suspicious_description(text: str) -> list[str]:
    """Heuristic scan. Catches the obvious; a paraphrasing attacker evades it, so pinning is the real control."""
    reasons = sorted({why for pat, why in SUSPICIOUS if pat.search(text)})
    if len(text) > MAX_DESCRIPTION:
        reasons.append("unusually long description")
    return reasons


def tool_hash(tool: dict) -> str:
    """Hash of everything the model will see about a tool: name, description and input schema."""
    canon = json.dumps({k: tool.get(k) for k in ("name", "description", "inputSchema")}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


class McpClient:
    def __init__(self, url: str, server_name: str = "weather"):
        self.url, self.server_name, self._id = url, server_name, 0

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
            return json.loads(r.read())["result"]

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list")["tools"]

    def call(self, name: str, args: dict) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": args})
        return "".join(c.get("text", "") for c in result["content"])


def pin_manifest(client: McpClient, allow_suspicious: bool = False) -> dict[str, str]:
    """The operator's one-time review step: refuse suspicious tools, otherwise return {tool name: hash} to pin.

    A real flow shows each full description to a human and stores the pins somewhere the server cannot write.
    """
    pins = {}
    for t in client.list_tools():
        reasons = suspicious_description(t["description"])
        if reasons and not allow_suspicious:
            raise ValueError(f"refusing to pin {t['name']!r}: {', '.join(reasons)}")
        pins[t["name"]] = tool_hash(t)
    return pins
