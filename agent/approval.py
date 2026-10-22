"""Human-in-the-loop gate for risky tool calls. The harness enforces it; the model cannot approve itself.

Flow: a risky call arrives -> a pending request is recorded and shown to a human with the EXACT arguments ->
the model is told the action has not happened. A human approves OUT OF BAND (`gate.approve(id)`, a UI button
or CLI prompt, never a tool). The model retries the identical call, which consumes that single-use approval.
Approval is bound to a digest of (tool, canonical args): changed arguments need a new approval.
"""
import hashlib
import json
import time

TIERS = {
    "read_file": 0, "fetch_url": 0, "lookup_customer": 0, "file_stats": 0, "call_api": 0,  # read-only
    "write_file": 1, "write_report": 1,  # reversible, confined writes
    "run_shell": 2, "send_email": 2,  # external effects
    "delete_file": 3, "make_payment": 3,  # irreversible / money
}
LABELS = {2: "EXTERNAL EFFECT", 3: "IRREVERSIBLE"}


def tier(name: str) -> int:
    return TIERS.get(name, 3)  # unknown tools are treated as the most dangerous


def digest(name: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"tool": name, "args": args}, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def preview(name: str, args: dict) -> str:
    """What the human sees. repr() quotes values, so newlines or fake 'APPROVED' text in arguments stay visible data."""
    shown = []
    for k, v in args.items():
        r = repr(v)
        shown.append(f"{k}={r[:300]}{'...(+%d chars)' % (len(r) - 300) if len(r) > 300 else ''}")
    return f"{name}({', '.join(shown)}) [{LABELS.get(tier(name), 'RISKY')}]"


class ApprovalGate:
    def __init__(self, decider=None, min_tier: int = 2, ttl: float = 300, max_actions: int = 3, clock=time.time):
        """decider(preview) -> True (approve now) / False (deny) / None (leave pending for out-of-band approval)."""
        self.decider, self.min_tier, self.ttl, self.max_actions, self.clock = decider, min_tier, ttl, max_actions, clock
        self.pending: dict[str, dict] = {}
        self._approved: dict[str, float] = {}  # digest -> expiry; single use
        self.performed = 0
        self.audit: list[tuple[str, str]] = []  # (event, preview), for review

    def needs_approval(self, name: str) -> bool:
        return tier(name) >= self.min_tier

    def check(self, name: str, args: dict) -> str | None:
        """None means proceed. Anything else is the message returned to the model instead of running the tool."""
        if not self.needs_approval(name):
            return None
        d, pv = digest(name, args), preview(name, args)
        exp = self._approved.pop(d, None)  # pop = single use, even if expired
        if exp is not None and self.clock() < exp:
            if self.performed >= self.max_actions:
                self.audit.append(("rate_limited", pv))
                return f"blocked by policy: at most {self.max_actions} risky actions per run"
            self.performed += 1
            self.audit.append(("performed", pv))
            return None
        pid = d[:12]
        self.pending[pid] = {"digest": d, "preview": pv}
        self.audit.append(("requested", pv))
        verdict = self.decider(pv) if self.decider else None
        if verdict is True:
            self.approve(pid)
            return self.check(name, args)
        if verdict is False:
            self.pending.pop(pid, None)
            self.audit.append(("denied", pv))
            return f"blocked by policy: a human denied {pv}"
        return (f"pending human approval (id={pid}): {pv}. The action has NOT been performed. "
                "Tell the user it needs their approval; do not retry until they confirm.")

    def approve(self, pid: str) -> None:
        """Out-of-band entry point for a human (CLI prompt, UI button). Deliberately not a tool."""
        p = self.pending.pop(pid)
        self._approved[p["digest"]] = self.clock() + self.ttl
        self.audit.append(("approved", p["preview"]))

    def deny(self, pid: str) -> None:
        p = self.pending.pop(pid)
        self.audit.append(("denied", p["preview"]))
