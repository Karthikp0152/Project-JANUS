"""Smoke test: every Milestone 2 module imports, and each function returns the agreed shape."""
from bench import metrics, run_eval
from janus import b1, baselines, compiler, gate, policies, probe_agent, rules, scanner, verifier, world_gen
from janus import pipeline
from janus.llm_client import FakeLLM
from janus.types import (
    DefenseRule,
    GateDecision,
    ProbeResult,
    RunResult,
    Scenario,
    ScanReport,
)

CFG = {"horizon_n": 3, "seed": 598}
VIOLATION = {"policy_id": "P4", "action_id": "close_ticket", "args": {"ticket_id": "T-104"}, "step": 0}
WITNESS = {"violation": VIOLATION, "prefix": []}
ACTION = {"action_id": "close_ticket", "tool": "close_ticket", "args": {"ticket_id": "T-104"}}


def has_shape(value, shape):
    return set(shape.__required_keys__) <= set(value)


def scenario():
    return world_gen.generate("seen", 1)[0]


def rule():
    return compiler.compile_rule(VIOLATION, {"id": "P4"}, {}, None, FakeLLM())


def test_generate_returns_requested_scenarios():
    scenarios = world_gen.generate("heldout", 3, seed=598)
    assert len(scenarios) == 3
    assert all(has_shape(s, Scenario) for s in scenarios)
    assert len({s["id"] for s in scenarios}) == 3


def test_policies_signatures():
    world = scenario()["world"]
    assert isinstance(policies.catalog(world), list)
    assert isinstance(policies.check(world, ACTION), list)
    assert policies.apply(world, ACTION) is not world
    assert isinstance(policies.reachable_violations(scenario(), 3), list)


def test_rules_signatures():
    assert isinstance(rules.FIELDS, dict)
    ok, message = rules.validate_schema(rule())
    assert isinstance(ok, bool) and isinstance(message, str)
    assert rules.enforce([rule()], ACTION, scenario()["world"]) in ("allow", "deny")


def test_verifier_signatures():
    decision = verifier.verify(rule(), WITNESS, scenario(), [])
    assert has_shape(decision, GateDecision)
    assert isinstance(verifier.make_variants(VIOLATION, scenario()["world"]), list)


def test_gate_signatures():
    a_rule = rule()
    decision = verifier.verify(a_rule, WITNESS, scenario(), [])
    exported = gate.export([decision], [a_rule], "briefing", canaries=[])
    assert set(exported) == {"rules", "briefing"}
    assert gate.evaluate_only([a_rule], ACTION, scenario()["world"]) in ("allow", "deny")
    assert issubclass(gate.GateViolation, Exception)


def test_agent_signatures():
    assert has_shape(probe_agent.probe(scenario()["world"], scenario(), CFG, FakeLLM()), ProbeResult)
    assert has_shape(rule(), DefenseRule)
    assert isinstance(compiler.write_briefing({}, FakeLLM()), str)
    assert issubclass(compiler.CompileError, Exception)
    assert isinstance(compiler.TEMPLATE_RULES, dict)


def test_systems_return_run_results():
    results = {
        "B0": baselines.run_b0(scenario(), CFG),
        "B1": b1.run_b1(scenario(), CFG, llm=FakeLLM()),
        "P": pipeline.run_p(scenario(), CFG, llm=FakeLLM()),
    }
    for system, result in results.items():
        assert has_shape(result, RunResult)
        assert result["system"] == system
        assert result["scenario_id"] == "seen-000"
        assert {"twin_dump", "llm_prompts", "logs", "probe_values"} <= set(result["artifacts"])


def test_bench_signatures():
    result = pipeline.run_p(scenario(), CFG, llm=FakeLLM())
    report = scanner.scan(result["artifacts"], [], result["exports"])
    assert has_shape(report, ScanReport)
    assert isinstance(metrics.compute([result], [scenario()], {}), dict)
    assert run_eval.main(["--split", "seen", "--system", "all", "--n", "1"]) == 0
