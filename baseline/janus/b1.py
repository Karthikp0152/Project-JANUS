"""Baseline B1 for Project JANUS. Owner: Mokshitha Mohan.

One model request with sanitized telemetry, a world summary and the policy set. No tools, no
replay and no rule repair. The client's standard re-ask on malformed JSON still applies (up to 2).
Rules are checked with V1 and V2 only, then deployed.
"""
from __future__ import annotations

import json
import time
from typing import Any

from aswa.rme import sanitize_value
from janus.compiler import KIND_HINT, normalize_rule, rule_schema, v1_problem, world_summary
from janus.llm_client import RECOVERED, LLMClient, PromptLeak, find_leak
from janus.types import DefenseRule, GateDecision, RunResult, Scenario

B1_SYSTEM = (
    "You are a single-shot baseline defense writer for a synthetic company in a defensive "
    "simulator. From the telemetry, world summary and policies, write one narrow rule for each "
    "policy you think is at risk. Use only the fields, operators and kinds in the schema. Use "
    "is_true or is_false for booleans. effect 'require' blocks when all conditions hold unless "
    "require_field is truthy."
)
RULE_KEYS = set(DefenseRule.__annotations__)


def _v2_problem(rule: DefenseRule, canaries: list[str]) -> str | None:
    """V2: pure rule, with no action, trace or tool-call fields, and no secrets."""
    extra = set(rule) - RULE_KEYS
    if extra:
        return f"non-rule fields: {sorted(extra)}"
    leak = find_leak(json.dumps(rule, ensure_ascii=False, default=str), canaries)
    return f"{leak} in rule" if leak else None


def run_b1(scenario: Scenario, cfg: Any, llm: Any = None) -> RunResult:
    """Run B1 on one scenario. ``llm=None`` builds the real client; tests inject FakeLLM."""
    started = time.perf_counter()
    client = llm if llm is not None else LLMClient(use_cache=cfg.get("use_cache", True))
    prompts_before = len(client.prompt_log)
    canaries = scenario.get("secrets") or []
    errors: list[str] = []
    rules: list[DefenseRule] = []
    gate_log: list[GateDecision] = []
    tokens_in = tokens_out = 0
    cost = 0.0

    world = world_summary(scenario["world"])
    payload = {
        "telemetry": sanitize_value(scenario.get("telemetry") or []),
        "world": world,
        "policies": [{"id": p["id"], "text": p["text"], "tool": p["tool"]} for p in scenario["policies"]],
    }
    messages = [
        {"role": "system", "content": f"{B1_SYSTEM} {KIND_HINT}"},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
    ]
    schema = {
        "type": "object",
        "required": ["rules"],
        "properties": {"rules": {"type": "array", "items": rule_schema()}},
    }

    try:
        result = client.chat_json("b1", messages, schema, scenario_id=scenario["id"], canaries=canaries)
    except PromptLeak as exc:
        errors.append(f"PromptLeak: {exc}")
    else:
        tokens_in, tokens_out, cost = result["tokens_in"], result["tokens_out"], result["cost_usd"]
        if result["data"] is None:
            errors.append(f"b1 LLM failed: {result['error']}")
        for index, raw in enumerate((result["data"] or {}).get("rules", [])):
            rule = normalize_rule(raw, f"b1-{scenario['id']}-{index}")
            v1 = v1_problem(rule)
            v2 = _v2_problem(rule, canaries)
            approved = v1 is None and v2 is None
            if approved:
                rules.append(rule)
            else:
                errors.append(f"{RECOVERED}{rule['id']} rejected: {v1 or v2}")
            gate_log.append(
                GateDecision(
                    rule_id=rule["id"],
                    status="approved" if approved else "rejected",
                    checks={"V1": v1 is None, "V2": v2 is None},
                    reason=v1 or v2 or "",
                    rounds=1,
                )
            )

    return RunResult(
        scenario_id=scenario["id"],
        system="B1",
        seed=cfg.get("seed", scenario.get("seed", 598)),
        horizon_n=cfg.get("horizon_n", 3),
        violations_found=[],
        rules_deployed=rules,
        gate_log=gate_log,
        exports={"rules": rules, "briefing": None},
        artifacts={
            "twin_dump": json.dumps(world, ensure_ascii=False, default=str),
            "llm_prompts": list(client.prompt_log[prompts_before:]),
            "logs": [f"b1 {scenario['id']}: {len(rules)} rules deployed, {len(errors)} errors"],
            "probe_values": [],
        },
        tokens={"tokens_in": tokens_in, "tokens_out": tokens_out},
        cost_usd=cost,
        latency_s=time.perf_counter() - started,
        errors=errors,
    )
