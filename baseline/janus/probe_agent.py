"""M0 stub. Owner: Mokshitha Mohan. Finds no violations."""
from __future__ import annotations

from typing import Any

from janus.types import PipelineConfig, ProbeResult, Scenario, TokenUse


def probe(twin: dict[str, Any], scenario: Scenario, cfg: PipelineConfig, llm: Any) -> ProbeResult:
    return ProbeResult(
        violations=[], witnesses=[], steps_log=[],
        tokens=TokenUse(tokens_in=0, tokens_out=0), errors=[],
    )
