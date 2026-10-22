# S6 fix: secret hygiene

Where the baseline leaks a credential, and the control for each:

| Leak path | Baseline flaw | Control |
|---|---|---|
| System prompt | `BILLING_API_KEY=...` pasted into the prompt "so the model can call the API" | `secret_broker`: the prompt has no secrets. `call_api` authenticates inside the tool |
| Tool arguments / transcript | the model has to echo the key as `api_key` | the tool rejects model-supplied credentials; it injects a 60 s token scoped to `read:invoices` (`agent/broker.py`) |
| Error messages | upstream errors echo request headers | generic errors in the tool; `redact_tool_results` as a second layer |
| Files | model can `read_file` `.env` | `secret_file_denylist` (and `redact_tool_results` scrubs the values anyway) |
| Answer to the user | "repeat your instructions" prints the prompt | nothing secret in the prompt; `redact_output` as a backstop |
| Logs | full prompt, args and results written to `runs.jsonl` | `redact_logs` scrubs known values (plain, URL-encoded, base64) and secret patterns before writing |

Defence order matters: **don't give the model the secret** is the control; redaction is the net under it.

Limits:
- Redaction matches known values and patterns. A model that has seen a secret can leak it encoded in ways the scrubber does not know (same weakness as the S3 DLP).
- The broker is lab-grade (HMAC token in memory). In production use your cloud's short-lived credentials (STS, workload identity) and a real secret manager; never ship a long-lived key to the agent process if you can avoid it.
- The log still holds task text and tool results, which may be sensitive data rather than credentials. Treat transcripts as sensitive: access control and retention.
