# S1 fix: quarantine and taint gate

Two independent layers, because neither is sufficient alone:

1. **Quarantine (dual-LLM pattern)** (`hardening["quarantine"]`): `fetch_url` no longer returns the page. A separate model call with **no tools** and an "untrusted data" system prompt summarises it, and only a length-capped plain-text summary reaches the privileged model. The injection never gets to talk to a model that can act.
2. **Taint gate** (`hardening["taint_gate"]`): once any untrusted content has been fetched, side effects are checked in code, not by the model:
   - `run_shell` is blocked.
   - `send_email` only to addresses the **user** wrote in the task.
   - dotfiles (like `.env`) cannot be read.

Why both: a summary from the quarantined model can still carry injected text (summaries are attacker-influenced too). The gate holds even if the quarantine leaks. The tests cover that case (`LeakyQuarantine`).

Limits: the gate is coarse (it also blocks legitimate reads of dotfiles after a fetch), and a summary could still mislead the user. Finer fix: per-value provenance (capability tracking) instead of a global taint flag.
