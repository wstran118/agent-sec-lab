# Security and ethics

## Intentionally vulnerable
Code under `agent/` (vulnerable configuration) and `attacks/` is deliberately insecure. **Never deploy it, expose it to a network, or give it real credentials or data.**

## Scope
- Exploits in this repo target only the containers defined in `docker-compose.yml`.
- Do not point these techniques at systems you do not own or have written permission to test.
- All secrets in this repo are fake canary strings (`CANARY-*`). All data is fictional.

## Reporting
Found a real vulnerability in the *lab tooling itself* (for example a container escape or a leaked key)? Open a GitHub issue, or email the maintainer for anything sensitive. Vulnerabilities in the agent code are planted on purpose and are not reportable.
