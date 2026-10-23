# agent-sec-lab

> **WARNING: INTENTIONALLY VULNERABLE. NEVER DEPLOY.**
> This project contains deliberately insecure code written for security education. Do not run it on a shared machine, expose it to a network, give it real credentials, or point its exploits at systems you do not own.

A vulnerable-by-design, tool-using AI agent lab: plant a flaw, exploit it, fix it, and prove both with an automated test. Fake data only (secrets are `CANARY-*` strings). Everything is designed to run inside Docker; the test suite runs locally with no API key.

**See it without running anything:** open [docs/demo/index.html](docs/demo/index.html) in a browser. It replays every scenario, vulnerable agent versus hardened agent, side by side. It is a recording of real runs of the lab code with a scripted worst-case model, not a live model. To publish it, enable GitHub Pages for the `docs/` folder; regenerate it with `uv run python -m demo.build`.

## Scenarios

| # | Scenario | OWASP LLM 2025 | OWASP Agentic 2026 | Write-up | Exploit | Fix |
|---|---|---|---|---|---|---|
| S1 | Indirect prompt injection | LLM01 | ASI01 | [s1](docs/writeups/s1-indirect-prompt-injection.md) | [attacks/s1_indirect_injection](attacks/s1_indirect_injection) | [fixes/s1_quarantine](fixes/s1_quarantine) |
| S2 | Over-permissioned tools | LLM06 | ASI02, ASI03 | [s2](docs/writeups/s2-over-permissioned-tools.md) | [attacks/s2_over_permissioned](attacks/s2_over_permissioned) | [fixes/s2_least_privilege](fixes/s2_least_privilege) |
| S3 | Data exfiltration | LLM02, LLM05 | ASI02 | [s3](docs/writeups/s3-data-exfiltration.md) | [attacks/s3_exfiltration](attacks/s3_exfiltration) | [fixes/s3_egress](fixes/s3_egress) |
| S4 | MCP-style rug pull / tool poisoning | LLM03, LLM01 | ASI04 | [s4](docs/writeups/s4-mcp-rug-pull.md) | [attacks/s4_mcp_rug_pull](attacks/s4_mcp_rug_pull) | [fixes/s4_mcp_pinning](fixes/s4_mcp_pinning) |
| S5 | Insecure output handling | LLM05 | ASI05 | [s5](docs/writeups/s5-insecure-output-handling.md) | [attacks/s5_output_handling](attacks/s5_output_handling) | [fixes/s5_safe_sinks](fixes/s5_safe_sinks) |
| S6 | Secrets in context and logs | LLM02, LLM07 | ASI03 | [s6](docs/writeups/s6-secrets-leakage.md) | [attacks/s6_secrets_leakage](attacks/s6_secrets_leakage) | [fixes/s6_secret_hygiene](fixes/s6_secret_hygiene) |
| S7 | Missing human-in-the-loop | LLM06 | ASI02, ASI09 | [s7](docs/writeups/s7-missing-human-in-the-loop.md) | [attacks/s7_missing_hitl](attacks/s7_missing_hitl) | [fixes/s7_confirmation](fixes/s7_confirmation) |
| S8 | Memory poisoning | LLM01, LLM04 | ASI06 | [s8](docs/writeups/s8-memory-poisoning.md) | [attacks/s8_memory_poisoning](attacks/s8_memory_poisoning) | [fixes/s8_memory_hygiene](fixes/s8_memory_hygiene) |

Full ID mapping (including MITRE ATLAS) with sources: [docs/mapping.md](docs/mapping.md). Results and what was *not* measured: [docs/results.md](docs/results.md). Blog-style summary: [docs/blog.md](docs/blog.md). Memory poisoning (S8) is the last scenario.

## Quickstart
```bash
cp .env.example .env   # add a dedicated, spend-capped API key (only needed for real-model runs)
pip install pre-commit && pre-commit install
uv run --group dev pytest                      # 177 tests, mock-model mode, no API key
docker compose up -d mock-web attacker-sink mcp-server   # lab services
docker compose --profile run run --rm agent "Summarise http://mock-web:8080/wiki.txt"   # real API, needs .env
```

Measure a real model against an attack (needs a key; prints how many runs leaked):
```bash
uv run python -m attacks.s1_indirect_injection.exploit -n 10 [--hardened]
uv run python -m attacks.s3_exfiltration.exploit --kind image -n 10 [--hardened]
```

## How the tests work
The attack tests use a deterministic stand-in model that obeys whatever untrusted content says, so they check *our controls*, not model luck. They say nothing about how often a particular real model falls for an attack; see [docs/results.md](docs/results.md).

## Ethics and scope
All exploits target only this lab's own containers. See [SECURITY.md](SECURITY.md).

## License
MIT
