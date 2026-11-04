"""M0 stub. Owner: Karthik Ponugoti. Returns an empty P result; the state machine comes next."""
from __future__ import annotations

from typing import Any

from janus.types import DEFAULT_HORIZON_N, DEFAULT_SEED, PipelineConfig, RunResult, Scenario, TokenUse


def run_p(scenario: Scenario, cfg: PipelineConfig, llm: Any = None) -> RunResult:
    return RunResult(
        scenario_id=scenario["id"], system="P", seed=cfg.get("seed", DEFAULT_SEED),
        horizon_n=cfg.get("horizon_n", DEFAULT_HORIZON_N), violations_found=[], rules_deployed=[],
        gate_log=[], exports={"rules": [], "briefing": None},
        artifacts={"twin_dump": "", "llm_prompts": [], "logs": [], "probe_values": []},
        tokens=TokenUse(tokens_in=0, tokens_out=0), cost_usd=0.0, latency_s=0.0, errors=[],
    )
