# S7: Missing human-in-the-loop on destructive actions

**Maps to:** LLM06 · ASI02, ASI09 · AML.T0101, AML.T0053 · mitigation AML.M0029 ([mapping](../mapping.md))

## The flaw
`delete_file`, `make_payment`, `send_email` and `run_shell` execute the moment the model asks. Any injection, misread request or model error becomes data loss, a payment or a message.

## The attack
A poisoned "cleanup" page makes the agent delete a signed contract, pay "Mallory Holdings" 9500, and email all staff a changed-wire-details message. The scripted model does exactly what the page says and ignores any "pending" or "blocked" reply, which is the worst case.

## Impact
Irreversible data destruction, financial loss and a phishing message from a trusted sender.

## The fix (`fixes/s7_confirmation`, `agent/approval.py`)
- **Risk tiers** (unknown tools default to the highest) and a gate on tier ≥ 2.
- **Exact preview:** the human sees the call with `repr`-quoted arguments, so a newline or fake "APPROVED" text inside an argument stays visible data.
- **Out-of-band approval:** `gate.approve(id)` is called by a UI or CLI, never by a tool. The model cannot approve itself.
- **Action-bound, single-use, expiring:** approval is tied to a digest of (tool, canonical args); changed arguments or a replay need a new approval.
- **Safe headless default:** with no decider the action stays pending forever.
- **Rate limit** on risky actions per run; **soft delete** to `.trash/`; **payee allow-list and payment cap**, so even a rushed approval has a bounded blast radius.

## Evidence
`tests/test_s7_human_in_the_loop.py` (16 tests): the exploit succeeds on the vulnerable agent; with the gate, headless and denied runs change nothing and the model is told the action was *not* performed; approval is bound to the exact call, single-use and expires; the rate limit holds even for approved actions; deletes are recoverable; approved payments still need a known payee and a sane amount. Attacks on the gate itself: a forged `confirmed: true` argument, injected "APPROVED" text in a file, newline spoofing in the preview, and the absence of any approval tool. Low-risk work never prompts a human.

## What this does not show
A gate is only as good as the person behind it: approval fatigue defeats it, which is why the threshold is high, the preview exact, and the payee list and cap exist as a second line. The preview shows what will run, not why; attacker-written email content still needs a human to read it. Tier assignment is a policy decision to revisit whenever a tool is added.
