"""`call_api`: a fake billing API client. INTENTIONALLY VULNERABLE (S6) unless hardening["secret_broker"] is on.

Vulnerable: the model must supply the API key (so the key lives in the system prompt, the tool arguments, the
transcript and the logs) and upstream errors echo the request headers back into the model's context.
Fixed: the tool injects a short-lived scoped token itself; the model never sees or sends a credential.
"""
import json

BILLING_SCHEMA = {
    "name": "call_api",
    "description": "Call the internal billing API (GET). Endpoints: /invoices.",
    "input_schema": {
        "type": "object",
        "properties": {"endpoint": {"type": "string"}, "api_key": {"type": "string"}},
        "required": ["endpoint"],
    },
}
INVOICES = [{"id": "INV-1", "customer": "Alice Example", "total": 120}, {"id": "INV-2", "customer": "Bob Example", "total": 75}]


def _service(tools, endpoint: str, auth: str) -> tuple[int, dict]:
    """The fake billing service: accepts the raw key (legacy) or a token scoped to read:invoices."""
    bearer = auth.removeprefix("Bearer ")
    if not (bearer == tools.broker.get("BILLING_API_KEY") or tools.broker.verify(bearer, "read:invoices")):
        return 401, {"error": "bad credentials"}
    if endpoint == "/invoices":
        return 200, {"invoices": INVOICES}
    return 404, {"error": "not found"}


def call_api(tools, endpoint: str, api_key: str | None = None) -> str:
    fixed = tools.cfg.hardening.get("secret_broker")
    if fixed:
        if api_key:
            raise PermissionError("credentials must not be supplied by the model; the tool injects them")
        headers = {"Authorization": f"Bearer {tools.broker.issue_token('read:invoices', ttl=60)}"}
    else:
        if not api_key:
            return "error: api_key is required"
        headers = {"Authorization": f"Bearer {api_key}"}
    status, body = _service(tools, endpoint, headers["Authorization"])
    if status == 200:
        return json.dumps(body)
    if fixed:
        return f"error: billing API returned {status}"
    # VULNERABLE (S6): verbose upstream error echoes the whole request, credentials included.
    return f"error: billing API returned {status} for {endpoint}; request headers: {headers}"
