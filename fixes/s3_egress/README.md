# S3 fix: egress controls

Three channels, three controls (all deterministic, none depends on the model behaving):

| Channel | Control |
|---|---|
| Markdown/HTML image or link in the answer (client auto-loads it) | `sanitize_markdown`: drop images, reference-style images/definitions, non-allow-listed links, raw `<img>/<script>/<iframe>`; redact secrets |
| `fetch_url` with data in the query string | host:port allow-list + DLP on the URL |
| `send_email` to an attacker | recipient domain allow-list + DLP on subject/body |

Layers: allow-lists stop the destination, DLP stops the data. The network-level equivalent (the `internal` Docker network, later an egress proxy) is the backstop.

Known limits (documented, tested as `xfail`):
- DLP is pattern-based; an attacker who gets the model to encode data (rot13, spelling it out, splitting across calls) bypasses it. Allow-lists, not DLP, are the real control.
- An allow-listed host that the attacker can also write to (for example a shared wiki) is still a channel.
