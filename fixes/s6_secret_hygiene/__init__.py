"""S6 fix: keep secrets out of context, tool output, answers and logs. See README.md.

    cfg.hardening = dict(HARDENING)
"""

HARDENING = {
    "secret_broker": True,  # no credentials in the prompt or tool args; tools inject short-lived scoped tokens
    "secret_file_denylist": (".env", ".pem", ".key", "id_rsa"),  # model cannot read credential files
    "redact_tool_results": True,  # known secret values and secret patterns are scrubbed from tool output
    "redact_output": True,  # ...and from the answer shown to the user
    "redact_logs": True,  # ...and from the transcript log
}
