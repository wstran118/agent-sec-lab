"""S7 fix: human approval of risky actions, soft delete, payee allow-list and payment cap. See README.md.

    gate = ApprovalGate(decider=ask_human)      # decider=None: actions stay pending (safe headless default)
    cfg.hardening = hardening(gate)
"""
from agent.approval import ApprovalGate


def hardening(gate: ApprovalGate, payees=("Acme Supplies Ltd",), payment_limit: float = 500.0) -> dict:
    return {
        "approval_gate": gate,  # tier >= 2 tools (shell, email, delete, payment) need a human OK of the exact args
        "soft_delete": True,  # delete_file moves to .trash/, recoverable
        "payee_allowlist": set(payees),  # even an approved payment must go to a known vendor...
        "payment_limit": payment_limit,  # ...and stay under a cap, so a rushed approval has a bounded blast radius
    }


def cli_decider(preview: str) -> bool:
    """Interactive approval for local runs: shows the exact call and waits for y/N."""
    return input(f"\nAPPROVE?  {preview}\n[y/N] ").strip().lower() == "y"
