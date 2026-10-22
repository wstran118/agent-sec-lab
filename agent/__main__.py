"""CLI: python -m agent "task".  Uses the real Anthropic API; needs ANTHROPIC_API_KEY."""
import sys

from .config import Config
from .llm import AnthropicModel
from .loop import run_agent

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit('usage: python -m agent "<task>"')
    cfg = Config()
    out = run_agent(" ".join(sys.argv[1:]), AnthropicModel(cfg.model, cfg.max_tokens), cfg)
    for c in out["tool_calls"]:
        print(f"[tool] {c['tool']}({c['input']})")
    print(out["final"])
