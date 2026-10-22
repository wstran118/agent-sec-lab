# S7 fix: human approval of risky actions

Baseline: `delete_file`, `make_payment`, `send_email` and `run_shell` execute the moment the model asks. An injected page, a misread request or a plain model mistake becomes data loss, a payment or an email.

| Control | What it does |
|---|---|
| Risk tiers (`agent/approval.py`) | 0 read, 1 reversible confined write, 2 external effect (email, shell), 3 irreversible (delete, payment). Unknown tools default to 3 |
| Approval gate | tier >= 2 calls are held. A human sees the **exact** call (`repr`-quoted arguments, so a newline or fake "APPROVED" text inside an argument is just visible data) |
| Out-of-band approval | `gate.approve(id)` is called by a UI/CLI, **not** a tool. The model cannot approve itself, and nothing in its messages or tool output counts as consent |
| Action-bound, single-use | approval is bound to a digest of (tool, canonical args). Changed arguments need a new approval. A replay needs a new approval. Approvals expire (TTL) |
| Safe default | with no decider the action stays pending forever (headless/CI = nothing risky happens) |
| Rate limit | at most N risky actions per run, so one rushed "yes" cannot be turned into a flood |
| Soft delete | deletion moves to `.trash/`, recoverable |
| Payee allow-list + cap | even an approved payment must go to a known vendor and stay under the limit: bounds the damage of approval fatigue |

Limits:
- A gate is only as good as the human behind it. Approval fatigue (clicking yes on everything) defeats it, which is why the tier threshold is high, the preview is exact, and the payee list and cap exist as a second line.
- The preview shows what will run, not why. If the *content* of an approved email is attacker-written, the human has to read it; S3's recipient allow-list and DLP still apply.
- Tier assignment is a policy decision; review it whenever a tool is added.
