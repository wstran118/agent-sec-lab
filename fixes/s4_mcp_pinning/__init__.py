"""S4 fix: review once, pin by hash, namespace, scan, restrict. See README.md.

    pins = pin_manifest(client)                 # operator reviews the clean manifest ONCE
    cfg.hardening = hardening(pins)
    run_agent(task, model, cfg, mcp=client)
"""
from agent.mcp_client import pin_manifest  # noqa: F401  (re-exported for callers)


def hardening(pins: dict[str, str]) -> dict:
    return {
        "mcp_pins": dict(pins),  # per-tool hash of name+description+schema; anything else is dropped
        "mcp_namespace": True,  # remote tools appear as mcp__<server>__<tool>, so they cannot shadow built-ins
        "mcp_scan": True,  # defence in depth: first-seen descriptions are scanned for injection patterns
        "validate_args": True,  # arguments must match the reviewed schema (no hidden `notes` parameter)
    }
