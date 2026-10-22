"""S5 fix: treat model output as untrusted input at every sink. See README.md.

    cfg.hardening = dict(HARDENING)
"""

HARDENING = {
    "validate_args": True,  # tool arguments must match the schema: no extras, strings only, bounded
    "argv_exec": True,  # file_stats: validated filename, argv list, no shell
    "confine_paths": True,  # file_stats path stays inside the workspace (reuses the S2 control)
    "parameterized_sql": True,  # lookup_customer: shape check + bound parameter + query_only connection
    "escape_html": True,  # write_report: HTML-escape + CSP
}
