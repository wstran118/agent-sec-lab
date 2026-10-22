"""Tiny outbound DLP: find secret-looking strings in text leaving the agent.

Deterministic and cheap, but NOT a complete control: it only sees what it has patterns for and what is not
encoded around them (see the xfail test in tests/test_s3_exfiltration.py). Use it with egress allow-lists.
"""
import base64
import re
from urllib.parse import quote, unquote

PATTERNS = [
    re.compile(r"CANARY-[A-Z0-9-]+"),  # lab canaries
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"sk-ant-[\w-]{8,}"),  # Anthropic-style key
    re.compile(r"(?i)\b(?:secret|password|passwd|api[_-]?key|token)\b\s*[=:]\s*\S{6,}"),
]
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def _views(text: str):
    yield text
    once = unquote(text)
    yield once
    yield unquote(once)
    for tok in B64_TOKEN.findall(once):
        try:
            yield base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_" if "-" in tok or "_" in tok else None).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001 - not base64
            pass


def find_secrets(text: str) -> list[str]:
    found = []
    for view in _views(str(text)):
        for p in PATTERNS:
            found += p.findall(view)
    return found


def scrub(text: str, known_values=()) -> str:
    """Redact exact known secret values (also their URL-encoded and base64 forms) and secret-looking patterns."""
    text = str(text)
    for v in known_values:
        if not v:
            continue
        for form in {v, quote(v), base64.b64encode(v.encode()).decode(), base64.urlsafe_b64encode(v.encode()).decode()}:
            text = text.replace(form, "[REDACTED]")
    return redact(text)


def redact(text: str) -> str:
    for p in PATTERNS:
        text = p.sub("[REDACTED]", text)
    return text
