"""S8 fix: memory is typed, provenance-aware, signed and expiring. See README.md.

    cfg.hardening = dict(HARDENING)
"""

HARDENING = {
    "memory_schema": True,  # only allow-listed, validated facts are stored, and only those are rendered to the model
    "memory_deny_tainted": True,  # no memory writes once untrusted content has been read in this session
    "memory_mac": True,  # the memory file is HMAC-signed; a tampered file is ignored entirely
    "memory_ttl": 30 * 24 * 3600,  # entries expire after 30 days
}
