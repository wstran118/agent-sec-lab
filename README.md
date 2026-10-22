# agent-sec-lab

> **WARNING: INTENTIONALLY VULNERABLE. NEVER DEPLOY.**
> This project contains deliberately insecure code written for security education. Do not run it on a shared machine, expose it to a network, give it real credentials, or point its exploits at systems you do not own.

A vulnerable-by-design, tool-using AI agent lab: plant a flaw, exploit it, fix it, test both. Fake data only. Everything runs inside Docker.

Status: baseline agent (M2). No vulnerabilities are exploited yet; the tools are deliberately unrestricted.

## Quickstart
```bash
uv run --group dev pytest                      # mock-model tests, no API key needed
docker compose up -d mock-web attacker-sink    # lab services
docker compose --profile run run --rm agent "Summarise http://mock-web:8080/wiki.txt"   # real API, needs .env
```

## Setup
```bash
cp .env.example .env   # add a dedicated, spend-capped API key
pip install pre-commit && pre-commit install
```

## Ethics and scope
All exploits target only this lab's own containers. See [SECURITY.md](SECURITY.md).

## License
MIT
