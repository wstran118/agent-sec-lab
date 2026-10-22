"""Lab configuration. Every hardening flag is OFF in the baseline; later milestones add fixes behind them."""
import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    model: str = field(default_factory=lambda: os.environ.get("AGENT_MODEL", "claude-haiku-5-5"))
    workspace: Path = field(default_factory=lambda: Path(os.environ.get("AGENT_WORKSPACE", ROOT / "data" / "workspace")))
    outbox: Path = field(default_factory=lambda: Path(os.environ.get("AGENT_OUTBOX", ROOT / "transcripts" / "outbox.jsonl")))
    transcript_dir: Path = field(default_factory=lambda: Path(os.environ.get("AGENT_TRANSCRIPTS", ROOT / "transcripts")))
    sink_url: str = field(default_factory=lambda: os.environ.get("SINK_URL", "http://attacker-sink:9000"))
    max_turns: int = 10
    max_tokens: int = 1024
    # Hardening toggles: empty means VULNERABLE. Fixes land in later milestones.
    hardening: dict = field(default_factory=dict)
