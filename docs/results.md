# Results

Run `uv run --group dev pytest` (no API key, no network beyond localhost). Last full run: **177 passed, 2 expected xfails**.

| Scenario | Tests | Exploit works on vulnerable agent | Fix blocks it | Documented bypass (`xfail`) |
|---|---|---|---|---|
| Baseline (loop, tools, services) | 5 | n/a | n/a | |
| S1 Indirect prompt injection | 8 | yes | yes (each layer alone, and when the quarantine leaks) | |
| S2 Over-permissioned tools | 21 | yes | yes | |
| S3 Data exfiltration (5 channels) | 24 + 1 | yes, all 5 | yes, all 5 | DLP evaded by rot13 |
| S4 MCP-style rug pull / poisoning / shadowing | 14 + 1 | yes | yes | heuristic scan evaded by paraphrase |
| S5 Insecure output handling (shell, SQL, HTML) | 50 | yes | yes | |
| S6 Secrets in context and logs | 19 | yes | yes | |
| S7 Missing human-in-the-loop | 16 | yes | yes | |
| S8 Memory poisoning (cross-session) | 20 | yes | yes | |

CI (GitHub Actions) runs the same tests plus gitleaks, pip-audit, a bandit high-severity gate and hadolint.

## What these numbers mean
- Each scenario has a test that **proves the vulnerability exists** and a test that **proves the fix works and the normal task still works**. A fix that only breaks the exploit is not counted.
- The model in the attack tests is a deterministic stand-in that obeys whatever the untrusted content says (the worst case). That isolates *our controls* from model behaviour, which is the right thing to test for the deterministic fixes. It tells you nothing about how likely a given real model is to fall for the attack.

## What was not measured
- **Real-model attack success rates.** `attacks/s1_indirect_injection/exploit.py` and `attacks/s3_exfiltration/exploit.py` measure a real model over N runs, with and without the fix. They have not been run for this write-up, so no rate is claimed. Run them with a spend-capped key to fill in this table.
- Docker images (the daemon was not available during development), live network egress enforcement.
- Anything about resource exhaustion (LLM10), multi-agent setups (ASI07, ASI08, ASI10) or misinformation (LLM09).

## Known limits of the fixes
| Fix | Limit |
|---|---|
| S1 taint gate | one global flag; blocks legitimate dotfile reads after any fetch. Per-value provenance would be better |
| S2 path confinement | resolve-then-open TOCTOU window; container filesystem is the backstop |
| S3 / S6 redaction and DLP | pattern-based; a model that has seen a secret can re-encode it |
| S4 pinning | does not help if a malicious tool is approved on day one |
| S5 HTML escaping | reports become plain text |
| S7 approval gate | approval fatigue; the preview shows what, not why |
| S8 memory | taint comes from known sources only (a user-uploaded poisoned file is not tracked); the schema is deliberately tiny; the signing key is in the process environment |
