from pathlib import Path

import agentcutter

REPO = Path(agentcutter.__file__).resolve().parents[2]
FIXTURES = REPO.parent / "forkline" / "test" / "fixtures"
BIN = REPO / "bin" / "forkline-timeline"


def fixture(name: str) -> Path:
    p = FIXTURES / name
    assert p.exists(), f"missing fixture {p}"
    return p


def all_fixtures() -> list[Path]:
    return sorted(FIXTURES.glob("timeline_*.jsonl"))
