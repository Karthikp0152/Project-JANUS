"""Smoke test of every Milestone 2 module, plus behaviour tests for run_b0 and run_p."""
import json

import pytest

from bench import metrics, run_eval
from janus import b1, baselines, compiler, gate, policies, probe_agent, rules, scanner, verifier, world_gen
from janus import pipeline
from janus.llm_client import BoundLLM, FakeLLM, LLMClient, PromptLeak
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


# ---------------------------------------------------------------------------
# run_b0: the adapter over frozen aswa
# ---------------------------------------------------------------------------
def real_scenario(split="seen"):
    return world_gen.generate(split, 1, seed=598)[0]


def test_b0_finds_and_maps_seen_violations_and_marks_rules_unverified():
    sc = real_scenario()
    before = json.dumps(sc, sort_keys=True)
    result = baselines.run_b0(sc, CFG)
    assert result["errors"] == []
    assert json.dumps(sc, sort_keys=True) == before, "the scenario must not be changed"
    assert {r["addresses_policy"] for r in result["rules_deployed"]} == {"P1", "P2", "P3", "P4"}
    assert result["exports"] == {"rules": result["rules_deployed"], "briefing": None}
    assert {v["action_id"] for v in result["violations_found"]} <= {
        "grant_access", "send_email", "create_payment", "close_ticket"
    }
    assert all(set(d["checks"]) == {"V1"} for d in result["gate_log"])
    assert result["tokens"] == {"tokens_in": 0, "tokens_out": 0}


def test_b0_p1_is_restricted_only_and_p3_uses_world_threshold():
    sc = real_scenario()
    rules_by_policy = {r["addresses_policy"]: r for r in baselines.run_b0(sc, CFG)["rules_deployed"]}
    label = next(c for c in rules_by_policy["P1"]["conditions"] if c["field"] == "folder.label")
    assert label["value"] == ["restricted"]
    assert rules_by_policy["P3"]["conditions"][0]["value"] == sc["world"]["thresholds"]["payment_dual_approval"]
    assert rules_by_policy["P3"]["require_field"] == "dual_approved"


def test_b0_keeps_raw_secrets_and_traces_out_of_scanner_inputs():
    for split in ("seen", "heldout", "benign"):
        sc = real_scenario(split)
        assert sc["secrets"]
        result = baselines.run_b0(sc, CFG)
        report = scanner.scan(result["artifacts"], sc["secrets"], result["exports"])
        assert (report["leaks"], report["escapes"]) == (0, 0), report["details"]


def test_b0_deploys_templates_on_heldout_but_cannot_address_those_policies():
    result = baselines.run_b0(real_scenario("heldout"), CFG)
    assert result["rules_deployed"], "B0 ignores the scenario's policies"
    assert {r["addresses_policy"] for r in result["rules_deployed"]} <= {"P1", "P2", "P3", "P4"}


def test_b0_stays_offline_when_a_key_is_configured(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("B0 must not call an LLM during evaluation")

    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    monkeypatch.setattr("aswa.learn.explain_countermeasure", fail)
    assert baselines.run_b0(real_scenario(), CFG)["errors"] == []


def test_b0_records_a_crash_as_failure_without_rules():
    sc = real_scenario()
    del sc["world"]["folders"]["payroll"]
    result = baselines.run_b0(sc, CFG)
    assert result["errors"] and result["errors"][0].startswith("B0 failed")
    assert result["rules_deployed"] == [] and result["exports"]["rules"] == []


# ---------------------------------------------------------------------------
# run_p: state machine, with teammates' modules replaced where behaviour matters
# ---------------------------------------------------------------------------
P_VIOLATION = {"policy_id": "P4", "action_id": "close_ticket", "args": {"ticket_id": "T-104"}, "step": 0}
P_PREFIX = [{"action_id": "comment_ticket", "tool": "comment_ticket", "args": {"ticket_id": "T-200", "comment": "x"}}]


def p_scenario(split="seen"):
    sc = real_scenario(split)
    return sc


def decision(rule, status, reason=""):
    return {"rule_id": rule["id"], "status": status, "checks": {f"V{i}": status == "approved" for i in range(1, 7)},
            "reason": reason, "rounds": 1}


def probe_finding(*violations):
    def probe(twin, scenario, cfg, llm):
        return {
            "violations": list(violations),
            "witnesses": [{"violation": v, "prefix": P_PREFIX} for v in violations],
            "steps_log": [], "tokens": {"tokens_in": 0, "tokens_out": 0}, "errors": [],
        }
    return probe


def scripted_verify(*statuses):
    queue = list(statuses)

    def verify(rule, witness, scenario, installed):
        return decision(rule, queue.pop(0), reason="V5 failed: blocks benign action")
    return verify


def test_p_abort_before_any_llm_when_a_canary_survives(monkeypatch):
    sc = p_scenario()
    sc["world"]["users"]["alex"]["note"] = sc["secrets"][0]  # a shape the mirror cannot redact

    class NoLLM:
        def __init__(self, *args, **kwargs):
            raise AssertionError("no LLM client may be built")

    monkeypatch.setattr(pipeline, "LLMClient", NoLLM)
    monkeypatch.setattr(pipeline.probe_agent, "probe", lambda *a: pytest.fail("probe must not run"))
    result = pipeline.run_p(sc, CFG)
    assert any("canary survived" in e for e in result["errors"])
    assert result["rules_deployed"] == []
    assert not any(sc["secrets"][0] in e for e in result["errors"])
    assert scanner.scan(result["artifacts"], sc["secrets"], result["exports"])["leaks"] > 0


def test_p_mirror_hides_contents_secrets_and_the_answer_key_from_the_probe(monkeypatch):
    sc = p_scenario()
    seen = {}

    def probe(twin, scenario, cfg, llm):
        seen.update(twin=twin, scenario=scenario)
        return probe_finding()(twin, scenario, cfg, llm)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert all(meta["contents"] == "[SANITIZED]" for meta in seen["twin"]["files"].values())
    assert sc["ground_truth"], "the original keeps its labels"
    assert seen["scenario"]["ground_truth"] == []
    assert seen["scenario"]["hidden_variants"] == [] and seen["scenario"]["benign_actions"] == []
    dump = json.dumps(seen["scenario"]["telemetry"]) + json.dumps(seen["twin"]) + result["artifacts"]["twin_dump"]
    assert not any(secret in dump for secret in sc["secrets"])


def test_p_approved_rule_is_deployed_and_compiler_gets_no_witness(monkeypatch):
    views = []
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, policy, twin_view, feedback, llm):
        views.append(twin_view)
        return original(violation, policy, twin_view, feedback, llm)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert [r["addresses_policy"] for r in result["rules_deployed"]] == ["P4"]
    assert result["exports"]["rules"] == result["rules_deployed"]
    assert [d["status"] for d in result["gate_log"]] == ["approved"]
    assert result["violations_found"] == [P_VIOLATION]
    assert set(views[0]) == {"world", "violation"}
    assert "T-200" not in json.dumps(views[0]["violation"]), "no witness prefix"
    assert {"close_ticket", "T-104", "comment_ticket", "T-200"} <= set(result["artifacts"]["probe_values"])
    assert "T-200" not in json.dumps(result["artifacts"]["logs"])


def test_p_repair_passes_the_verifier_reason_back_and_counts_rounds(monkeypatch):
    feedback = []
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, policy, twin_view, fb, llm):
        feedback.append(fb)
        return original(violation, policy, twin_view, fb, llm)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "approved"))
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert feedback == [None, "V5 failed: blocks benign action"]
    assert result["gate_log"][0]["status"] == "approved" and result["gate_log"][0]["rounds"] == 2
    assert len(result["rules_deployed"]) == 1


def test_p_escalates_after_three_rejections_and_reports_the_risk(monkeypatch):
    briefed = []

    def write_briefing(summary, llm):
        briefed.append(summary)
        return "Briefing."

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "rejected", "rejected"))
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["gate_log"][0]["status"] == "escalated" and result["gate_log"][0]["rounds"] == 3
    assert result["rules_deployed"] == [] and result["exports"]["rules"] == []
    assert [risk["policy"] for risk in briefed[0]["unresolved_risks"]] == ["P4"]
    assert "T-104" not in json.dumps(briefed[0]), "the briefing input holds no probe content"


def test_p_compile_errors_are_recorded_and_still_escalated(monkeypatch):
    def compile_rule(*args):
        raise compiler.CompileError("bad rule")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert len([e for e in result["errors"] if "CompileError" in e]) == 3
    assert result["gate_log"][0]["status"] == "escalated"
    assert result["rules_deployed"] == []


def test_p_ignores_violations_of_enforced_and_unconfigured_policies(monkeypatch):
    held_out = {"policy_id": "H4", "action_id": "delete_audit", "args": {"entry_id": "A-001"}, "step": 0}
    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION, held_out))
    monkeypatch.setattr(pipeline.verifier, "verify", lambda rule, *a: pytest.fail("nothing to verify"))
    benign = pipeline.run_p(p_scenario("benign"), CFG, llm=FakeLLM())
    assert benign["violations_found"] == [] and benign["rules_deployed"] == []

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(held_out))
    seen = pipeline.run_p(p_scenario("seen"), CFG, llm=FakeLLM())
    assert seen["violations_found"] == [] and seen["rules_deployed"] == []


def test_p_compiles_one_rule_per_policy_and_action(monkeypatch):
    other_args = {**P_VIOLATION, "args": {"ticket_id": "T-200"}}
    calls = []
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, *rest):
        calls.append(violation)
        return original(violation, *rest)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION, other_args))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert calls == [P_VIOLATION]


def test_p_prompt_leak_aborts_with_a_masked_error(monkeypatch):
    sc = p_scenario()

    def probe(*args):
        raise PromptLeak(f"found {sc['secrets'][0]} in prompt")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert result["errors"] and "PromptLeak" in result["errors"][0]
    assert not any(sc["secrets"][0] in e for e in result["errors"])
    assert result["rules_deployed"] == []


def test_p_export_refusal_deploys_nothing(monkeypatch):
    def refuse(*args, **kwargs):
        raise gate.GateViolation("trace in export")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "export", refuse)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["rules_deployed"] == [] and result["exports"]["rules"] == []
    assert any("GateViolation" in e for e in result["errors"])


def test_p_refused_briefing_is_dropped_but_rules_stay(monkeypatch):
    original = pipeline.gate.export

    def export(decisions, rules, briefing, canaries=None):
        if briefing:
            raise gate.GateViolation("canary in briefing")
        return original(decisions, rules, briefing, canaries)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "export", export)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert len(result["rules_deployed"]) == 1
    assert result["exports"]["briefing"] is None and len(result["exports"]["rules"]) == 1


def test_p_uses_a_fallback_briefing_when_writing_fails(monkeypatch):
    def fail(summary, llm):
        raise RuntimeError("model down")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.compiler, "write_briefing", fail)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert "Deployed rules" in result["exports"]["briefing"]
    assert any("Brief" in e for e in result["errors"])


def test_p_counts_only_this_runs_tokens_and_prompts(monkeypatch):
    llm = FakeLLM()
    llm.usage.update(tokens_in=100, tokens_out=50)
    llm.prompt_log.append("from an earlier run")

    def probe(twin, scenario, cfg, client):
        client.usage["tokens_in"] += 7
        client.usage["tokens_out"] += 3
        client.prompt_log.append("this run")
        return probe_finding()(twin, scenario, cfg, client)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, client: "Briefing.")
    result = pipeline.run_p(p_scenario(), CFG, llm=llm)
    assert result["tokens"] == {"tokens_in": 7, "tokens_out": 3}
    assert result["artifacts"]["llm_prompts"] == ["this run"]


def test_harness_runs_b0_and_p_end_to_end():
    runners = {
        "B0": baselines.run_b0,
        "P": lambda scenario, cfg: pipeline.run_p(scenario, cfg, llm=FakeLLM()),  # never the real, paid client
    }
    out = run_eval.evaluate("seen", ["B0", "P"], 1, 598, runners=runners)
    assert {r["system"] for r in out["results"]} == {"B0", "P"}
    assert out["metrics"]["overall"]["B0"]["unverified_deploy_rate"]["value"] == 1.0
    assert out["metrics"]["overall"]["B0"]["secret_leak_rate"]["value"] == 0.0


# ---------------------------------------------------------------------------
# Regressions found in review
# ---------------------------------------------------------------------------
def test_p_verifier_gets_no_answer_key_or_hidden_variants(monkeypatch):
    sc = p_scenario()
    seen = {}

    def verify(rule, witness, scenario, installed):
        seen.update(scenario)
        return decision(rule, "approved")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", verify)
    pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert sc["hidden_variants"] and sc["ground_truth"], "the original keeps them for the harness"
    assert seen["hidden_variants"] == [] and seen["ground_truth"] == []
    assert seen["benign_actions"] == sc["benign_actions"]
    assert seen["secrets"] == sc["secrets"]
    assert all(meta["contents"] == "[SANITIZED]" for meta in seen["world"]["files"].values())
    assert seen["world"]["folders"] == sc["world"]["folders"], "structure and labels stay intact"
    assert not any(secret in json.dumps(seen["telemetry"]) for secret in sc["secrets"])


def test_p_gate_refusal_reports_the_risk_instead_of_an_all_clear(monkeypatch):
    summaries = []

    def refuse(*args, **kwargs):
        raise gate.GateViolation("refused")

    def write_briefing(summary, llm):
        summaries.append(summary)
        return "Briefing."

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "export", refuse)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert [risk["policy"] for risk in summaries[0]["unresolved_risks"]] == ["P4"]
    assert summaries[0]["approved_rules"] == []
    assert result["gate_log"][0]["status"] == "escalated"


def test_p_probe_crash_briefing_does_not_read_as_an_all_clear(monkeypatch):
    def crash(*args):
        raise RuntimeError("model down")

    def fail(summary, llm):
        raise RuntimeError("model down")

    monkeypatch.setattr(pipeline.probe_agent, "probe", crash)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", fail)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert "may be incomplete" in result["exports"]["briefing"]


def test_p_prompt_leak_while_briefing_keeps_completed_work(monkeypatch):
    def leak(summary, llm):
        raise PromptLeak("blocked")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.compiler, "write_briefing", leak)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert len(result["rules_deployed"]) == 1 and len(result["exports"]["rules"]) == 1
    assert "Deployed rules" in result["exports"]["briefing"], "the fallback needs no LLM"
    assert result["violations_found"] == [P_VIOLATION]
    assert "T-200" in result["artifacts"]["probe_values"]
    assert any("PromptLeak" in e for e in result["errors"])


def test_p_unexpected_export_error_deploys_nothing_and_keeps_artifacts(monkeypatch):
    llm = FakeLLM()

    def probe(twin, scenario, cfg, client):
        client.prompt_log.append("sent to the model")
        return probe_finding(P_VIOLATION)(twin, scenario, cfg, client)

    def broken(*args, **kwargs):
        raise TypeError("bad export")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "export", broken)
    result = pipeline.run_p(p_scenario(), CFG, llm=llm)
    assert result["rules_deployed"] == [] and result["exports"]["rules"] == []
    assert "sent to the model" in result["artifacts"]["llm_prompts"]
    assert any("TypeError" in e for e in result["errors"])


def test_p_unexpected_error_in_a_later_state_does_not_escape_run_p(monkeypatch):
    llm = FakeLLM()

    def probe(twin, scenario, cfg, client):
        client.prompt_log.append("sent to the model")
        return probe_finding(P_VIOLATION)(twin, scenario, cfg, client)

    def broken(*args):
        raise KeyError("summary")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline, "_summary", broken)
    result = pipeline.run_p(p_scenario(), CFG, llm=llm)
    assert "sent to the model" in result["artifacts"]["llm_prompts"]
    assert len(result["rules_deployed"]) == 1
    assert any("KeyError" in e for e in result["errors"])


def test_p_abort_with_a_shared_client_reports_none_of_its_history():
    sc = p_scenario()
    sc["world"]["users"]["alex"]["note"] = sc["secrets"][0]
    llm = FakeLLM()
    llm.usage.update(tokens_in=100, tokens_out=50)
    llm.prompt_log.append("from an earlier run")
    result = pipeline.run_p(sc, CFG, llm=llm)
    assert result["tokens"] == {"tokens_in": 0, "tokens_out": 0}
    assert result["artifacts"]["llm_prompts"] == []
    assert result["cost_usd"] == 0.0


def test_p_masks_secrets_in_errors_the_probe_reports(monkeypatch):
    sc = p_scenario()

    def probe(twin, scenario, cfg, llm):
        found = probe_finding()(twin, scenario, cfg, llm)
        found["errors"] = [f"bad output near {sc['secrets'][0]}", "x" * 1000]
        return found

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert len(result["errors"]) == 2
    assert not any(sc["secrets"][0] in e for e in result["errors"])
    assert all(len(e) <= 300 for e in result["errors"])


def test_b0_twin_dump_covers_the_world_so_the_leak_gate_treats_it_like_p():
    sc = real_scenario()
    sc["world"]["users"]["alex"]["note"] = sc["secrets"][0]
    result = baselines.run_b0(sc, CFG)
    assert result["errors"] == []
    assert scanner.scan(result["artifacts"], sc["secrets"], result["exports"])["leaks"] > 0
    assert "[SANITIZED]" in result["artifacts"]["twin_dump"]


def canary_run(monkeypatch, evaluate):
    summaries = []

    def write_briefing(summary, llm):
        summaries.append(summary)
        return "Briefing."

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", lambda *a: {**template_rule(), "id": "rule-P4-close_ticket"})
    monkeypatch.setattr(pipeline.gate, "evaluate_only", evaluate)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    return pipeline.run_p(p_scenario(), CFG, llm=FakeLLM()), summaries[0]


def test_p_canary_denied_leaves_no_open_risk(monkeypatch):
    result, summary = canary_run(monkeypatch, lambda *a: "deny")
    assert summary["canary"] == {"denied": 1, "checked": 1}
    assert summary["unresolved_risks"] == []
    assert len(result["rules_deployed"]) == 1


def test_p_canary_allowed_reports_the_risk(monkeypatch):
    result, summary = canary_run(monkeypatch, lambda *a: "allow")
    assert summary["canary"] == {"denied": 0, "checked": 1}
    assert [risk["policy"] for risk in summary["unresolved_risks"]] == ["P4"]
    assert len(result["rules_deployed"]) == 1
    assert result["errors"] == [], "a failed check is a risk, measured by the block rate, not a run failure"


def test_p_canary_error_reports_the_risk(monkeypatch):
    def broken(*args):
        raise RuntimeError("endpoint down")

    result, summary = canary_run(monkeypatch, broken)
    assert [risk["policy"] for risk in summary["unresolved_risks"]] == ["P4"]
    assert any("Canary" in e for e in result["errors"])


def test_p_refused_llm_briefing_falls_back_and_keeps_the_risk(monkeypatch):
    original = pipeline.gate.export

    def export(decisions, rules, briefing, canaries=None):
        if briefing == "Written by the model.":
            raise gate.GateViolation("canary in briefing")
        return original(decisions, rules, briefing, canaries)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "rejected", "rejected"))
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Written by the model.")
    monkeypatch.setattr(pipeline.gate, "export", export)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert "Unresolved risks: P4" in result["exports"]["briefing"]


def test_p_prompt_leak_while_compiling_leaves_an_honest_record(monkeypatch):
    second = {"policy_id": "P1", "action_id": "grant_access", "args": {"folder": "payroll", "principal": "alex"}, "step": 0}
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, *rest):
        if violation["policy_id"] == "P1":
            raise PromptLeak("blocked")
        return original(violation, *rest)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION, second))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda *a: pytest.fail("no LLM call after a leak"))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["rules_deployed"] == []
    assert not any(d["status"] == "approved" for d in result["gate_log"])
    assert "P4" in result["exports"]["briefing"] and "P1" in result["exports"]["briefing"]
    assert any("PromptLeak" in e for e in result["errors"])


def test_p_compile_error_keeps_the_verifier_feedback_for_the_next_round(monkeypatch):
    feedback = []
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, policy, twin_view, fb, llm):
        feedback.append(fb)
        if len(feedback) == 2:
            raise compiler.CompileError("bad output")
        return original(violation, policy, twin_view, fb, llm)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "approved"))
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert feedback[2] == "V5 failed: blocks benign action"
    assert result["gate_log"][0]["rounds"] == 3 and result["gate_log"][0]["status"] == "approved"


@pytest.mark.parametrize("canary", ["CANARY-\u00e91", 'CANARY-"q', "CANARY-\\b"])
def test_p_aborts_on_a_surviving_canary_with_special_characters(monkeypatch, canary):
    sc = p_scenario()
    sc["secrets"] = [canary]
    sc["world"]["users"]["alex"]["note"] = canary
    monkeypatch.setattr(pipeline.probe_agent, "probe", lambda *a: pytest.fail("probe must not run"))
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert any("canary survived" in e for e in result["errors"])


def test_scanners_see_a_non_ascii_canary_in_both_twin_dumps():
    sc = real_scenario()
    sc["secrets"] = ["CANARY-\u00e91"]
    sc["world"]["users"]["alex"]["note"] = sc["secrets"][0]
    for result in (baselines.run_b0(sc, CFG), pipeline.run_p(sc, CFG, llm=FakeLLM())):
        assert scanner.scan(result["artifacts"], sc["secrets"], result["exports"])["leaks"] > 0


def test_b0_rules_all_pass_the_schema_check():
    result = baselines.run_b0(real_scenario(), CFG)
    assert len(result["gate_log"]) == 4
    assert all(d["checks"]["V1"] is True for d in result["gate_log"]), result["gate_log"]


# ---------------------------------------------------------------------------
# bind() and the "recovered:" contract with bench.metrics
# ---------------------------------------------------------------------------
def test_p_gives_every_agent_a_client_bound_to_this_scenario(monkeypatch):
    clients = {}
    original_compile = pipeline.compiler.compile_rule

    def probe(twin, scenario, cfg, client):
        clients["probe"] = client
        return probe_finding(P_VIOLATION)(twin, scenario, cfg, client)

    def compile_rule(violation, policy, twin_view, feedback, client):
        clients["compile"] = client
        return original_compile(violation, policy, twin_view, feedback, client)

    def write_briefing(summary, client):
        clients["brief"] = client
        return "Briefing."

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert set(clients) == {"probe", "compile", "brief"}
    assert all(isinstance(client, BoundLLM) for client in clients.values())


def test_p_bound_client_blocks_a_canary_in_any_prompt(monkeypatch):
    sc = p_scenario()
    schema = {"type": "object"}

    def probe(twin, scenario, cfg, client):
        client.chat_json("probe", [{"role": "user", "content": sc["secrets"][0]}], schema)
        pytest.fail("the prompt should have been blocked")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert any("PromptLeak" in e for e in result["errors"])


def test_p_works_with_a_real_client_that_refuses_unbound_calls(monkeypatch):
    client = LLMClient(transport=lambda *a: pytest.fail("no model call expected"), use_cache=False)

    def write_briefing(summary, llm):
        with pytest.raises(PromptLeak):
            llm.chat_json("brief", [{"role": "user", "content": sc["secrets"][0]}], {"type": "object"})
        return "Briefing."

    sc = p_scenario()
    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding())
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    result = pipeline.run_p(sc, CFG, llm=client)
    assert result["errors"] == []


def recovered_only(result):
    return result["errors"] and all(e.startswith("recovered:") for e in result["errors"])


def real_failure(result):
    return any(not e.startswith("recovered:") for e in result["errors"])


def test_p_compile_failure_then_approval_is_recovered_and_completes(monkeypatch):
    calls = []
    original = pipeline.compiler.compile_rule

    def compile_rule(violation, *rest):
        calls.append(violation)
        if len(calls) == 1:
            raise compiler.CompileError("bad output")
        return original(violation, *rest)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert recovered_only(result)
    assert metrics._completed(result)


def test_p_probe_faults_it_handled_are_recovered(monkeypatch):
    def probe(twin, scenario, cfg, llm):
        found = probe_finding()(twin, scenario, cfg, llm)
        found["errors"] = ["invalid call: unknown action", "falling back to the Q-learner"]
        return found

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert len(result["errors"]) == 2 and recovered_only(result)
    assert metrics._completed(result)


def test_p_fallback_briefing_is_recovered(monkeypatch):
    def fail(summary, llm):
        raise RuntimeError("model down")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding())
    monkeypatch.setattr(pipeline.compiler, "write_briefing", fail)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert recovered_only(result) and "Deployed rules" in result["exports"]["briefing"]
    assert metrics._completed(result)


def test_p_escalation_alone_adds_no_error(monkeypatch):
    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "rejected", "rejected"))
    monkeypatch.setattr(pipeline.gate, "evaluate_only", lambda *a: "allow")
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Briefing.")
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["gate_log"][0]["status"] == "escalated"
    assert result["errors"] == []
    assert metrics._completed(result)


def test_p_compile_failures_that_end_escalated_are_real_failures(monkeypatch):
    def compile_rule(*args):
        raise compiler.CompileError("bad rule")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", compile_rule)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert real_failure(result) and not metrics._completed(result)


def test_p_real_failures_have_no_prefix(monkeypatch):
    def leak(summary, llm):
        raise PromptLeak("blocked")

    def refuse(*args, **kwargs):
        raise gate.GateViolation("refused")

    def crash(*args):
        raise RuntimeError("crash")

    def scenario_run(**patches):
        with monkeypatch.context() as m:
            m.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
            m.setattr(pipeline.probe_agent, "probe", patches.get("probe", probe_finding(P_VIOLATION)))
            m.setattr(pipeline.gate, "evaluate_only", patches.get("evaluate", lambda *a: "deny"))
            if "brief" in patches:
                m.setattr(pipeline.compiler, "write_briefing", patches["brief"])
            if "export" in patches:
                m.setattr(pipeline.gate, "export", patches["export"])
            return pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())

    for result in (
        scenario_run(brief=leak),
        scenario_run(export=refuse),
        scenario_run(probe=crash),
        scenario_run(evaluate=crash),
    ):
        assert real_failure(result), result["errors"]
        assert not metrics._completed(result)

    surviving = p_scenario()
    surviving["world"]["users"]["alex"]["note"] = surviving["secrets"][0]
    aborted = pipeline.run_p(surviving, CFG, llm=FakeLLM())
    assert real_failure(aborted) and not metrics._completed(aborted)


def test_p_a_briefing_the_gate_refuses_is_a_real_failure_even_with_the_fallback(monkeypatch):
    original = pipeline.gate.export

    def export(decisions, rules, briefing, canaries=None):
        if briefing == "Written by the model.":
            raise gate.GateViolation("canary in briefing")
        return original(decisions, rules, briefing, canaries)

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding())
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Written by the model.")
    monkeypatch.setattr(pipeline.gate, "export", export)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert "Deployed rules" in result["exports"]["briefing"]
    assert real_failure(result) and not metrics._completed(result)


@pytest.mark.parametrize("split", ["seen", "heldout", "benign"])
def test_p_runs_mokshithas_real_agents_offline_without_leaks(split):
    sc = real_scenario(split)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    report = scanner.scan(result["artifacts"], sc["secrets"], result["exports"])
    assert (report["leaks"], report["escapes"]) == (0, 0), report["details"]
    assert isinstance(result["exports"]["briefing"], str)
    assert result["artifacts"]["llm_prompts"], "the real agents went through the client"
    if split == "benign":
        assert result["violations_found"] == [] and result["rules_deployed"] == []


# ---------------------------------------------------------------------------
# Third review
# ---------------------------------------------------------------------------
def test_p_text_from_write_briefing_is_not_an_all_clear_after_a_failure(monkeypatch):
    def crash(*args):
        raise RuntimeError("model down")

    # The real write_briefing returns its own text when the model fails, instead of raising.
    monkeypatch.setattr(pipeline.probe_agent, "probe", crash)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Unresolved risks: none.")
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["exports"]["briefing"].startswith("Unresolved risks: none.")
    assert "may be incomplete" in result["exports"]["briefing"]


def test_p_recovered_faults_do_not_trigger_the_incomplete_warning(monkeypatch):
    summaries = []

    def probe(twin, scenario, cfg, llm):
        found = probe_finding()(twin, scenario, cfg, llm)
        found["errors"] = ["invalid call: unknown action"]
        return found

    def write_briefing(summary, llm):
        summaries.append(summary)
        return "Briefing."

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    monkeypatch.setattr(pipeline.compiler, "write_briefing", write_briefing)
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["exports"]["briefing"] == "Briefing."
    assert summaries[0]["errors"] == 0


def test_p_surviving_canary_still_gives_the_operator_a_briefing():
    sc = p_scenario()
    sc["world"]["users"]["alex"]["note"] = sc["secrets"][0]
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert "may be incomplete" in result["exports"]["briefing"]
    assert result["artifacts"]["llm_prompts"] == [], "the briefing needs no LLM"
    assert sc["secrets"][0] not in result["exports"]["briefing"]


def test_p_masking_handles_overlapping_and_empty_secrets(monkeypatch):
    sc = p_scenario()
    sc["secrets"] = ["", "CANARY-AB", "CANARY-ABCDEF"]

    def probe(twin, scenario, cfg, llm):
        found = probe_finding()(twin, scenario, cfg, llm)
        found["errors"] = ["near CANARY-ABCDEF end"]
        return found

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe)
    result = pipeline.run_p(sc, CFG, llm=FakeLLM())
    assert result["errors"] == ["recovered: Probe: near [REDACTED] end"]
    assert metrics._completed(result)


def test_b0_failing_late_gets_no_discovery_credit(monkeypatch):
    def broken(rule):
        raise RuntimeError("schema check crashed")

    monkeypatch.setattr(baselines.rules, "validate_schema", broken)
    result = baselines.run_b0(real_scenario(), CFG)
    assert result["errors"] and result["violations_found"] == [] and result["rules_deployed"] == []


def test_reported_seed_defaults_to_the_scenario_seed():
    sc = real_scenario()
    sc["seed"] = 7
    assert baselines.run_b0(sc, {})["seed"] == 7
    assert pipeline.run_p(sc, {}, llm=FakeLLM())["seed"] == 7
    assert baselines.run_b0(sc, {"seed": 9})["seed"] == 9


# ---------------------------------------------------------------------------
# Template rules count as recovered faults
# ---------------------------------------------------------------------------
def template_rule(policy_id="P4"):
    return {
        "id": f"template-{policy_id}", "kind": "workflow_rule", "applies_to": "close_ticket",
        "conditions": [{"field": "ticket.comment_count", "op": "==", "value": 0}], "effect": "deny",
        "require_field": None, "addresses_policy": policy_id, "rationale": "Template rule.",
    }


def test_p_deployed_template_rule_is_a_recovered_fault(monkeypatch):
    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", lambda *a: template_rule())
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "evaluate_only", lambda *a: "deny")
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Briefing.")
    result = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert result["errors"] == ["recovered: Compile: fell back to template-P4"]
    assert metrics._completed(result)
    assert result["exports"]["briefing"] == "Briefing.", "a recovered fault adds no incomplete warning"


def test_p_template_rule_that_never_deploys_is_not_recorded(monkeypatch):
    def refuse(*args, **kwargs):
        raise gate.GateViolation("refused")

    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", lambda *a: template_rule())
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("rejected", "rejected", "rejected"))
    rejected = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert not any("fell back" in e for e in rejected["errors"])

    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "export", refuse)
    refused = pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())
    assert not any("fell back" in e for e in refused["errors"])


def test_p_llm_written_rule_is_not_recorded_as_a_template(monkeypatch):
    rule = {**template_rule(), "id": "rule-P4-close_ticket"}
    monkeypatch.setattr(pipeline.probe_agent, "probe", probe_finding(P_VIOLATION))
    monkeypatch.setattr(pipeline.compiler, "compile_rule", lambda *a: rule)
    monkeypatch.setattr(pipeline.verifier, "verify", scripted_verify("approved"))
    monkeypatch.setattr(pipeline.gate, "evaluate_only", lambda *a: "deny")
    monkeypatch.setattr(pipeline.compiler, "write_briefing", lambda summary, llm: "Briefing.")
    assert pipeline.run_p(p_scenario(), CFG, llm=FakeLLM())["errors"] == []
