# Framework mapping

Verified 2026-10-22 against primary sources:

- **OWASP Top 10 for LLM Applications 2025**: <https://genai.owasp.org/llm-top-10/>
- **OWASP Top 10 for Agentic Applications 2026** (published 2025-12-09): titles read from the official PDF, <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **MITRE ATLAS v5.6.0**: technique and mitigation IDs read from the project's data file, <https://github.com/mitre-atlas/atlas-data>

Scenario-to-category assignments are my judgement; where a scenario spans categories the primary one is listed first. IDs and titles are copied from the sources, so re-check them when those frameworks release new versions.

| # | Scenario | OWASP LLM 2025 | OWASP Agentic 2026 | MITRE ATLAS technique | ATLAS mitigation used |
|---|---|---|---|---|---|
| S1 | Indirect prompt injection | LLM01 Prompt Injection | ASI01 Agent Goal Hijack | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0099 AI Agent Tool Data Poisoning | AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data; AML.M0032 Segmentation of AI Agent Components |
| S2 | Over-permissioned tools | LLM06 Excessive Agency | ASI02 Tool Misuse and Exploitation; ASI03 Identity and Privilege Abuse | AML.T0053 AI Agent Tool Invocation | AML.M0028 AI Agent Tools Permissions Configuration |
| S3 | Data exfiltration | LLM02 Sensitive Information Disclosure; LLM05 Improper Output Handling | ASI02 Tool Misuse and Exploitation | AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0025 Exfiltration via Cyber Means | AML.M0033 Input and Output Validation for AI Agent Components |
| S4 | Tool-description poisoning / rug pull | LLM03 Supply Chain; LLM01 Prompt Injection | ASI04 Agentic Supply Chain Vulnerabilities; ASI02 | AML.T0110 AI Agent Tool Poisoning; AML.T0104 Publish Poisoned AI Agent Tool; AML.T0011.002 Poisoned AI Agent Tool | AML.M0014 Verify AI Artifacts (closest match to hash pinning) |
| S5 | Insecure output handling | LLM05 Improper Output Handling | ASI05 Unexpected Code Execution (RCE) | AML.T0053 AI Agent Tool Invocation | AML.M0033 Input and Output Validation for AI Agent Components |
| S6 | Secrets in context and logs | LLM02 Sensitive Information Disclosure; LLM07 System Prompt Leakage | ASI03 Identity and Privilege Abuse | AML.T0055 Unsecured Credentials; AML.T0083 Credentials from AI Agent Configuration; AML.T0057 LLM Data Leakage | AML.M0028 AI Agent Tools Permissions Configuration |
| S7 | Missing human-in-the-loop | LLM06 Excessive Agency | ASI02 Tool Misuse and Exploitation; ASI09 Human-Agent Trust Exploitation (approval fatigue) | AML.T0101 Data Destruction via AI Agent Tool Invocation; AML.T0053 | AML.M0029 Human In-the-Loop for AI Agent Actions |
| S8 | Memory poisoning | LLM01 Prompt Injection (persisted); LLM04 Data and Model Poisoning (loosest fit: stored data the model later consumes) | ASI06 Memory & Context Poisoning | AML.T0080.000 AI Agent Context Poisoning: Memory | AML.M0031 Memory Hardening |

## Notes on judgement calls

- **S4 mitigation:** ATLAS has no mitigation named for tool-manifest pinning. M0014 (Verify AI Artifacts) is the nearest, since a pin verifies a tool definition against a reviewed hash. The official ASI02 text also points at tool definitions as an ASI04 concern, which is why S4 lists ASI04 first.
- **S7 and ASI09:** the missing gate itself is ASI02 (an agent doing risky things unchecked). ASI09 is about an agent manipulating the human, which is the failure mode of a gate that exists but is rubber-stamped; the fix README addresses it with exact previews, payee allow-lists and caps.
- **S5 and ASI05:** the lab never runs model-built commands for real (`agent/shellsim.py` lists what a shell would have started), but the flaw class is the same as ASI05.
- **S8 and LLM08/RAG:** the lab has no embeddings or retrieval index, so LLM08 and AML.T0070 RAG Poisoning are not claimed; the memory store is a plain typed key-value file.
- **Not mapped:** LLM09 Misinformation, LLM10 Unbounded Consumption, ASI07 Inter-Agent Communication, ASI08 Cascading Failures and ASI10 Rogue Agents are outside this lab's scope (single agent, no multi-agent setup). The loop has a turn cap, but resource exhaustion is not tested.
