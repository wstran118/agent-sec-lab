"""S1 fix: quarantine untrusted text + taint-gated side effects. See README.md.

Enable in code with `cfg.hardening = dict(HARDENING)` or via the CLI with AGENT_HARDENING=s1.
"""

HARDENING = {"quarantine": True, "taint_gate": True}
