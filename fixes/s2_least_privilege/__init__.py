"""S2 fix: least privilege. See README.md.

    cfg.hardening = dict(HARDENING)
    run_agent(task, model, cfg, allowed_tools=PROFILES["read_only"])
"""

HARDENING = {
    "confine_paths": True,  # realpath containment: no '..', absolute paths or symlinks out of the workspace
    "write_dirs": ("out",),  # writes only under workspace/out
    "shell_allowlist": ("ls", "wc", "date"),  # fixed read-only commands, no metacharacters, paths confined
}

# Per-task tool grants: give each task only what it needs.
PROFILES = {
    "read_only": {"read_file"},
    "summarise_web": {"fetch_url", "read_file", "write_file"},
    "notify": {"read_file", "send_email"},
}
