"""Tests for probe_agent, compiler and b1. No network.

janus.rules and janus.policies are replaced by small local fakes built from COORDINATION 11.4 and
12.5, so these tests stay offline and do not depend on teammates' branches.
"""
import copy
import json
import sys
import types

import pytest

from janus import b1, compiler, probe_agent
from janus.compiler import CompileError, TEMPLATE_RULES, compile_rule, rule_schema, write_briefing
from janus.llm_client import FakeLLM, LLMClient, PromptLeak
from janus.probe_agent import PROBE_SCHEMA, TOOL_ARGS, guard, probe
from janus.types import ALL_TOOLS

FIELDS = {
    name: None
    for name in (
        "amount", "dual_approved", "public", "approved", "role", "verification_ticket", "bank",
        "principal.external", "to.external", "attachment.sensitivity", "folder.label",
        "file.sensitivity", "ticket.comment_count",
    )
}


def fake_catalog(world):
    return [
        {
            "action_id": "grant_payroll",
            "tool": "grant_access",
            "arg_choices": {"folder": ["payroll"], "principal": ["alex", "jane"]},
        },
        {
            "action_id": "comment_t1",
            "tool": "comment_ticket",
            "arg_choices": {"ticket_id": ["T-1"], "comment": ["checked"]},
        },
        {"action_id": "close_t1", "tool": "close_ticket", "arg_choices": {"ticket_id": ["T-1"]}},
    ]


def fake_check(world, action):
    if action["tool"] == "grant_access" and world["users"][action["args"]["principal"]]["external"]:
        return ["P1"]
    if action["tool"] == "close_ticket" and not world["tickets"]["T-1"]["comments"]:
        return ["P4"]
    return []


def fake_apply(world, action):
    new = copy.deepcopy(world)
    if action["tool"] == "comment_ticket":
        new["tickets"]["T-1"]["comments"].append(action["args"]["comment"])
    return new


def fake_validate_schema(rule):
    if rule["kind"] == "bad_kind":
        return False, "kind not allowed"
    return True, ""


@pytest.fixture(autouse=True)
def fake_teammate_modules(monkeypatch):
    rules = types.ModuleType("janus.rules")
    rules.FIELDS = FIELDS
    rules.validate_schema = fake_validate_schema
    policies = types.ModuleType("janus.policies")
    policies.catalog = fake_catalog
    policies.check = fake_check
    policies.apply = fake_apply
    monkeypatch.setitem(sys.modules, "janus.rules", rules)
    monkeypatch.setitem(sys.modules, "janus.policies", policies)


@pytest.fixture
def world():
    return {
        "users": {
            "alex": {"role": "staff", "external": False, "email": "alex@acme.example"},
            "jane": {"role": "contractor", "external": True, "email": "jane@vendor.example"},
        },
        "folders": {"payroll": {"acl": [], "label": "restricted"}},
        "files": {"pay.xlsx": {"folder": "payroll", "sensitivity": "restricted", "contents": "SECRET-BODY"}},
        "tickets": {"T-1": {"status": "open", "comments": ["private ticket note"], "kind": "it"}},
        "thresholds": {"payment_dual_approval": 750},
    }


@pytest.fixture
def scenario(world):
    world["tickets"]["T-1"]["comments"] = []
    return {
        "id": "seen-001",
        "split": "seen",
        "seed": 598,
        "world": world,
        "policies": [
            {"id": "P1", "family": "P1", "text": "No payroll access for externals", "tool": "grant_access"},
            {"id": "P4", "family": "P4", "text": "No close without comment", "tool": "close_ticket"},
        ],
        "enforced_policy_ids": [],
        "telemetry": [{"type": "login", "note": "password=CANARY-tele1"}, {"token": "CANARY-tele2"}],
        "secrets": ["CANARY-tele1", "CANARY-tele2"],
        "ground_truth": [],
        "benign_actions": [],
        "hidden_variants": [],
    }


GRANT_JANE = {"action_id": "grant_payroll", "args": {"folder": "payroll", "principal": "jane"}}
GRANT_ALEX = {"action_id": "grant_payroll", "args": {"folder": "payroll", "principal": "alex"}}
COMMENT = {"action_id": "comment_t1", "args": {"ticket_id": "T-1", "comment": "checked"}}
CLOSE = {"action_id": "close_t1", "args": {"ticket_id": "T-1"}}
ONE_STEP = {"episodes": 1, "horizon_n": 1, "seed": 598}

GOOD_RULE = {
    "kind": "sharing_rule",
    "applies_to": "share_link",
    "conditions": [
        {"field": "public", "op": "is_true"},
        {"field": "file.sensitivity", "op": "in", "value": ["restricted"]},
    ],
    "effect": "deny",
    "require_field": None,
    "addresses_policy": "H1",
    "rationale": "No public links for restricted files.",
}
H1 = {"id": "H1", "family": "H1", "text": "No restricted file shared by public link", "tool": "share_link"}
H1_VIOLATION = {"policy_id": "H1", "action_id": "share_pay", "args": {"file": "pay.xlsx", "public": True}, "step": 0}
P1 = {"id": "P1", "family": "P1", "text": "No payroll access for externals", "tool": "grant_access"}
P1_VIOLATION = {"policy_id": "P1", "action_id": "grant_payroll", "args": {"folder": "payroll", "principal": "jane"}, "step": 0}


# ---- probe -----------------------------------------------------------------------------------
def test_tool_args_match_coordination_11_4_exactly():
    expected = {
        "grant_access": ["folder", "principal"],
        "send_email": ["to", "attachment"],
        "create_payment": ["amount", "payee", "dual_approved"],
        "comment_ticket": ["ticket_id", "comment"],
        "close_ticket": ["ticket_id"],
        "share_link": ["file", "public"],
        "change_role": ["principal", "role", "approved"],
        "update_vendor_bank": ["vendor", "bank", "verification_ticket"],
        "delete_audit": ["entry_id"],
    }
    assert PROBE_SCHEMA["properties"]["args"]["x-tool-args"] == expected
    assert set(TOOL_ARGS) == set(ALL_TOOLS)


def test_prompt_shows_the_arg_names_for_every_tool(scenario):
    fake = FakeLLM({"probe": CLOSE})
    probe(scenario["world"], scenario, ONE_STEP, fake)
    assert "verification_ticket" in fake.prompt_log[0]
    assert "grant_payroll" in fake.prompt_log[0]


def test_finds_a_violation_and_builds_records(scenario):
    result = probe(scenario["world"], scenario, ONE_STEP, FakeLLM({"probe": GRANT_JANE}))
    assert result["violations"] == [
        {"policy_id": "P1", "action_id": "grant_payroll", "args": GRANT_JANE["args"], "step": 0}
    ]
    assert result["witnesses"][0]["prefix"] == []
    assert "reward=+9.9" in result["steps_log"][0]
    assert result["errors"] == []
    assert result["tokens"]["tokens_in"] > 0


def test_violation_records_hold_no_trace(scenario):
    cfg = {"episodes": 1, "horizon_n": 2}
    result = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": [GRANT_ALEX, GRANT_JANE]}))
    assert set(result["violations"][0]) == {"policy_id", "action_id", "args", "step"}
    assert result["witnesses"][0]["prefix"][0]["args"]["principal"] == "alex"


def test_later_steps_keep_the_prefix(scenario):
    cfg = {"episodes": 1, "horizon_n": 2}
    result = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": [COMMENT, GRANT_JANE]}))
    witness = result["witnesses"][0]
    assert witness["violation"]["step"] == 1
    assert [a["action_id"] for a in witness["prefix"]] == ["comment_t1"]


def test_each_episode_starts_from_a_fresh_copy(scenario):
    # Ep 0 comments then closes (safe). Ep 1 closes first, which only violates P4 on a fresh twin.
    cfg = {"episodes": 2, "horizon_n": 2}
    result = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": [COMMENT, CLOSE, CLOSE, GRANT_ALEX]}))
    assert [v["policy_id"] for v in result["violations"]] == ["P4"]
    assert result["violations"][0]["step"] == 0


def test_twin_is_never_changed(scenario):
    before = copy.deepcopy(scenario["world"])
    probe(scenario["world"], scenario, {"episodes": 2, "horizon_n": 3}, FakeLLM({"probe": COMMENT}))
    assert scenario["world"] == before


def test_repeated_violation_is_counted_once(scenario):
    result = probe(scenario["world"], scenario, {"episodes": 2, "horizon_n": 1}, FakeLLM({"probe": GRANT_JANE}))
    assert len(result["violations"]) == 1
    assert "reward=-0.1" in result["steps_log"][1]


def test_enforced_policies_are_not_reported(scenario):
    scenario["enforced_policy_ids"] = ["P1", "P4"]
    result = probe(scenario["world"], scenario, ONE_STEP, FakeLLM({"probe": GRANT_JANE}))
    assert result["violations"] == []


def test_unconfigured_policies_are_not_reported(scenario):
    scenario["policies"] = scenario["policies"][1:]
    result = probe(scenario["world"], scenario, ONE_STEP, FakeLLM({"probe": GRANT_JANE}))
    assert result["violations"] == []


def test_unknown_catalog_id_is_invalid_with_reward_minus_5(scenario):
    fake = FakeLLM({"probe": {"action_id": "rm_rf"}})
    result = probe(scenario["world"], scenario, ONE_STEP, fake)
    assert result["violations"] == []
    assert "reward=-5.0" in result["steps_log"][0]
    assert "unknown action_id" in result["errors"][0]
    assert fake.calls == ["probe"]  # the guard handled it: no retry and no fallback


@pytest.mark.parametrize(
    "reply,reason",
    [
        ({"action_id": "close_t1", "args": {}}, "args for close_ticket"),
        ({"action_id": "close_t1", "args": {"ticket_id": "T-1", "path": "/"}}, "args for close_ticket"),
        ({"action_id": "close_t1", "args": {"ticket_id": "T-999"}}, "not in arg_choices"),
    ],
)
def test_guard_rejects_bad_args(reply, reason):
    action, problem = guard(reply, fake_catalog({}))
    assert action is None
    assert reason in problem


def test_guard_accepts_a_null_choice():
    entry = {"action_id": "mail", "tool": "send_email", "arg_choices": {"to": ["a@b.c"], "attachment": [None]}}
    action, problem = guard({"action_id": "mail", "args": {"to": "a@b.c", "attachment": None}}, [entry])
    assert problem is None
    assert action["tool"] == "send_email"


def test_malformed_json_retries_then_uses_the_q_learner(scenario):
    fake = FakeLLM({"probe": "this is not json"})
    result = probe(scenario["world"], scenario, {"episodes": 5, "horizon_n": 3, "seed": 598}, fake)
    assert fake.calls == ["probe"] * 3
    assert result["errors"]
    assert any(line.startswith("qlearn") for line in result["steps_log"])
    assert {v["policy_id"] for v in result["violations"]} == {"P1", "P4"}


def test_q_learner_keeps_what_the_llm_already_found(scenario):
    cfg = {"episodes": 1, "horizon_n": 2, "seed": 598}
    fake = FakeLLM({"probe": [GRANT_JANE, "bad", "bad", "bad"]})
    result = probe(scenario["world"], scenario, cfg, fake)
    assert result["violations"][0]["args"]["principal"] == "jane"
    assert any(line.startswith("llm") for line in result["steps_log"])
    assert any(line.startswith("qlearn") for line in result["steps_log"])


def test_q_learner_is_repeatable_with_the_same_seed(scenario):
    cfg = {"episodes": 1, "horizon_n": 3, "seed": 7}
    first = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": "bad"}))
    second = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": "bad"}))
    assert first["steps_log"] == second["steps_log"]


def test_prompt_leak_aborts_the_probe(scenario, monkeypatch):
    def leaky_catalog(world):
        return [{"action_id": "x", "tool": "close_ticket", "arg_choices": {"ticket_id": ["CANARY-tele1"]}}]

    monkeypatch.setattr(sys.modules["janus.policies"], "catalog", leaky_catalog)
    fake = FakeLLM()
    with pytest.raises(PromptLeak):
        probe(scenario["world"], scenario, ONE_STEP, fake)
    assert fake.calls == []


def test_probe_prompt_shows_entity_classes_and_episode(scenario):
    fake = FakeLLM({"probe": CLOSE})
    probe(scenario["world"], scenario, {"episodes": 2, "horizon_n": 1}, fake)
    assert "folder_labels" in fake.prompt_log[0]
    assert "SECRET-BODY" not in fake.prompt_log[0]
    assert fake.prompt_log[0] != fake.prompt_log[1]


def test_failed_call_also_uses_the_q_learner(scenario):
    fake = FakeLLM({"probe": lambda messages: ValueError("rejected")})
    result = probe(scenario["world"], scenario, {"episodes": 1, "horizon_n": 2, "seed": 1}, fake)
    assert fake.calls == ["probe"]
    assert any(line.startswith("qlearn") for line in result["steps_log"])


def test_probe_works_with_the_default_fake(scenario):
    result = probe(scenario["world"], scenario, {"episodes": 1, "horizon_n": 3}, FakeLLM())
    assert result["errors"] == []
    assert len(result["steps_log"]) == 3


# ---- compile_rule ----------------------------------------------------------------------------
def test_schema_is_built_from_fields_and_allowed_lists():
    schema = rule_schema()
    condition = schema["properties"]["conditions"]["items"]["properties"]
    assert condition["field"]["enum"] == list(FIELDS)
    assert "vendor.verified" not in condition["field"]["enum"]
    assert "is_true" in condition["op"]["enum"]
    assert schema["properties"]["applies_to"]["enum"] == list(ALL_TOOLS)


def test_compile_returns_a_valid_rule_with_a_safe_id(world):
    rule = compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": GOOD_RULE}))
    assert rule["addresses_policy"] == "H1"
    assert rule["conditions"][0]["value"] is None
    assert rule["id"].startswith("rule-H1-")
    assert "share_pay" not in rule["id"]


def test_unbound_real_client_refuses_to_send(world):
    sent = []
    client = LLMClient(transport=lambda *args: sent.append(args) or ("{}", 0, 0), use_cache=False)
    with pytest.raises(ValueError, match="canaries are required"):
        compile_rule(H1_VIOLATION, H1, world, None, client)
    with pytest.raises(ValueError, match="canaries are required"):
        write_briefing({}, client)
    assert sent == []


def test_minimal_policy_and_empty_summary_work_with_fake(world):
    # Karthik's test_pipeline calls the agents this way.
    assert compile_rule(P1_VIOLATION, {"id": "P1"}, {}, None, FakeLLM())["addresses_policy"] == "P1"
    assert isinstance(write_briefing({}, FakeLLM()), str)


def test_non_string_feedback_is_refused(world):
    fake = FakeLLM({"compile": GOOD_RULE})
    with pytest.raises(TypeError):
        compile_rule(H1_VIOLATION, H1, world, {"witness": {"prefix": ["grant_x"]}}, fake)
    assert fake.calls == []


def test_long_feedback_is_cut(world):
    fake = FakeLLM({"compile": GOOD_RULE})
    compile_rule(H1_VIOLATION, H1, world, "x" * 600 + "END", fake)
    assert "END" not in fake.prompt_log[0]


@pytest.mark.parametrize(
    "condition,reason",
    [
        ({"field": "public", "op": "==", "value": True}, "use is_true or is_false"),
        ({"field": "amount", "op": ">"}, "needs a value"),
        ({"field": "file.sensitivity", "op": "in", "value": "restricted"}, "needs a list"),
        ({"field": "amount", "op": ">", "value": "lots"}, "needs a number"),
    ],
)
def test_bad_condition_shapes_are_rejected_and_fed_back(world, condition, reason):
    fake = FakeLLM({"compile": {**GOOD_RULE, "conditions": [condition]}})
    with pytest.raises(CompileError, match=reason):
        compile_rule(H1_VIOLATION, H1, world, None, fake)
    assert reason in fake.prompt_log[-1]


def test_rule_retry_alternates_roles(world):
    bad = {**GOOD_RULE, "addresses_policy": "H2"}
    fake = FakeLLM({"compile": [bad, GOOD_RULE]})
    compile_rule(H1_VIOLATION, H1, world, None, fake)
    assert [m["role"] for m in json.loads(fake.prompt_log[1])] == ["system", "user", "assistant", "user"]


def test_rule_id_is_stable_per_policy_and_tool(world):
    other_args = {**H1_VIOLATION, "args": {"file": "other.xlsx", "public": True}, "step": 2}
    first = compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": GOOD_RULE}))
    second = compile_rule(other_args, H1, world, None, FakeLLM({"compile": GOOD_RULE}))
    assert first["id"] == second["id"] == "rule-H1-share_link"


def test_verifier_feedback_reaches_the_prompt(world):
    fake = FakeLLM({"compile": GOOD_RULE})
    compile_rule(H1_VIOLATION, H1, world, "V4 failed: variant still allowed", fake)
    assert "V4 failed: variant still allowed" in fake.prompt_log[0]


def test_invented_field_is_rejected_and_the_error_fed_back(world):
    bad = {**GOOD_RULE, "conditions": [{"field": "vendor.verified", "op": "is_true"}]}
    fake = FakeLLM({"compile": [bad, GOOD_RULE]})
    rule = compile_rule(H1_VIOLATION, H1, world, None, fake)
    assert rule["conditions"][0]["field"] == "public"
    assert "value not allowed" in fake.prompt_log[1]


def test_validate_schema_failure_is_fed_back(world, monkeypatch):
    monkeypatch.setattr(sys.modules["janus.rules"], "validate_schema", lambda rule: (False, "op not allowed here"))
    fake = FakeLLM({"compile": GOOD_RULE})
    with pytest.raises(CompileError, match="op not allowed here"):
        compile_rule(H1_VIOLATION, H1, world, None, fake)
    assert "op not allowed here" in fake.prompt_log[-1]


def test_rule_for_the_wrong_policy_or_tool_is_rejected(world):
    wrong_policy = {**GOOD_RULE, "addresses_policy": "H2"}
    wrong_tool = {**GOOD_RULE, "applies_to": "send_email"}
    with pytest.raises(CompileError, match="addresses_policy"):
        compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": wrong_policy}))
    with pytest.raises(CompileError, match="applies_to"):
        compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": wrong_tool}))


def test_held_out_policy_raises_compile_error_when_retries_fail(world):
    fake = FakeLLM({"compile": {"kind": "not a real kind"}})
    with pytest.raises(CompileError):
        compile_rule(H1_VIOLATION, H1, world, None, fake)


def test_seen_policy_falls_back_to_its_template(world):
    rule = compile_rule(P1_VIOLATION, P1, world, None, FakeLLM({"compile": "garbage"}))
    assert rule["id"] == "template-P1"


def test_template_uses_the_world_threshold_and_stays_unchanged(world):
    p3 = {"id": "P3", "family": "P3", "text": "No big payment without approval", "tool": "create_payment"}
    violation = {"policy_id": "P3", "action_id": "pay", "args": {"amount": 999}, "step": 0}
    rule = compile_rule(violation, p3, world, None, FakeLLM({"compile": "garbage"}))
    assert rule["conditions"][0]["value"] == 750
    assert TEMPLATE_RULES["P3"]["conditions"][0]["value"] == 500


@pytest.mark.parametrize("policy_id", sorted(TEMPLATE_RULES))
def test_templates_only_use_known_fields_and_kinds(policy_id):
    template = TEMPLATE_RULES[policy_id]
    policy = {"id": policy_id, "family": policy_id, "text": "", "tool": template["applies_to"]}
    assert compiler.rule_problem(template, policy) is None
    assert all(c["field"] in FIELDS for c in template["conditions"])
    assert template["kind"] in compiler.rule_schema()["properties"]["kind"]["enum"]


def test_templates_cover_only_the_seen_policies():
    assert set(TEMPLATE_RULES) == {"P1", "P2", "P3", "P4"}


def test_empty_conditions_allowed_only_for_audit_deletes(world):
    h4 = {"id": "H4", "family": "H4", "text": "No audit entry deleted", "tool": "delete_audit"}
    violation = {"policy_id": "H4", "action_id": "del", "args": {"entry_id": "a1"}, "step": 0}
    good = {**GOOD_RULE, "kind": "audit_rule", "applies_to": "delete_audit", "conditions": [], "addresses_policy": "H4"}
    assert compile_rule(violation, h4, world, None, FakeLLM({"compile": good}))["conditions"] == []
    with pytest.raises(CompileError, match="must not be empty"):
        compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": {**GOOD_RULE, "conditions": []}}))


def test_require_rule_needs_a_field(world):
    bad = {**GOOD_RULE, "effect": "require", "require_field": None}
    with pytest.raises(CompileError, match="require_field"):
        compile_rule(H1_VIOLATION, H1, world, None, FakeLLM({"compile": bad}))


def test_prompt_holds_no_file_contents_or_ticket_text(world):
    fake = FakeLLM({"compile": GOOD_RULE})
    compile_rule(H1_VIOLATION, H1, {"world": world, "violation": H1_VIOLATION}, None, fake)
    prompt = fake.prompt_log[0]
    assert "SECRET-BODY" not in prompt
    assert "private ticket note" not in prompt
    assert "alex@acme.example" not in prompt
    assert "folder_labels" in prompt
    assert "restricted" in prompt


def test_compile_scans_for_canaries(world):
    world["folders"]["CANARY-x"] = {"label": "public"}
    fake = FakeLLM({"compile": GOOD_RULE})
    with pytest.raises(PromptLeak):
        compile_rule(H1_VIOLATION, H1, world, None, fake.bind("s", ["CANARY-x"]))
    assert fake.calls == []


def test_exact_twin_view_shape_is_read(world):
    fake = FakeLLM({"compile": GOOD_RULE})
    compile_rule(H1_VIOLATION, H1, {"world": world, "violation": H1_VIOLATION}, None, fake)
    prompt = json.loads(json.loads(fake.prompt_log[0])[1]["content"])
    assert prompt["world"]["folder_labels"] == {"payroll": "restricted"}


def test_witness_violation_equals_its_listed_violation(scenario):
    cfg = {"episodes": 1, "horizon_n": 2}
    result = probe(scenario["world"], scenario, cfg, FakeLLM({"probe": [GRANT_JANE, CLOSE]}))
    assert [w["violation"] for w in result["witnesses"]] == result["violations"]


def test_default_fake_compiles_for_seen_and_held_out_policies(world):
    assert compile_rule(P1_VIOLATION, P1, world, None, FakeLLM())["addresses_policy"] == "P1"
    assert compile_rule(H1_VIOLATION, H1, world, None, FakeLLM())["addresses_policy"] == "H1"


# ---- write_briefing --------------------------------------------------------------------------
SUMMARY = {
    "scenario_id": "seen-001",
    "approved_rules": [{"id": "rule-P1-grant_access", "policy": "P1", "rationale": "Blocks externals."}],
    "unresolved_risks": [{"policy": "H2", "text": "No admin role without approval"}],
    "canary": {"denied": 1, "checked": 2},
    "errors": 0,
}


def test_briefing_reads_the_pipeline_summary():
    fake = FakeLLM({"brief": {"briefing": "All good."}})
    assert write_briefing(SUMMARY, fake) == "All good."
    prompt = fake.prompt_log[0]
    for text in ("rule-P1-grant_access", "Blocks externals.", "No admin role without approval", "denied"):
        assert text in prompt


def test_briefing_drops_traces_at_every_level():
    fake = FakeLLM({"brief": {"briefing": "ok"}})
    summary = {
        **SUMMARY,
        "trace": ["top_level_trace"],
        "approved_rules": [{"id": "r1", "policy": "P1", "args": {"to": "nested_arg"}, "witness": "nested_witness"}],
        "unresolved_risks": [{"policy": "H2", "prefix": ["nested_prefix"]}, "bare_string_trace"],
    }
    write_briefing(summary, fake)
    for text in ("top_level_trace", "nested_arg", "nested_witness", "nested_prefix", "bare_string_trace"):
        assert text not in fake.prompt_log[0]


def test_briefing_scans_for_canaries():
    summary = {**SUMMARY, "approved_rules": [{"id": "CANARY-x", "policy": "P1", "rationale": "r"}]}
    fake = FakeLLM()
    with pytest.raises(PromptLeak):
        write_briefing(summary, fake.bind("s", ["CANARY-x"]))
    assert fake.calls == []


def test_briefing_falls_back_to_plain_text():
    text = write_briefing(SUMMARY, FakeLLM({"brief": "bad"}))
    assert "rule-P1-grant_access" in text
    assert "H2" in text

# ---- run_b1 ----------------------------------------------------------------------------------
B1_RULE = {**GOOD_RULE, "kind": "firewall_rule", "applies_to": "grant_access", "addresses_policy": "P1"}


def test_b1_makes_one_call_and_deploys_the_rule(scenario):
    fake = FakeLLM({"b1": {"rules": [B1_RULE]}})
    result = b1.run_b1(scenario, {"horizon_n": 3}, llm=fake)
    assert fake.calls == ["b1"]
    assert result["system"] == "B1"
    assert result["scenario_id"] == "seen-001"
    assert result["rules_deployed"][0]["id"] == "b1-seen-001-0"
    assert result["exports"] == {"rules": result["rules_deployed"], "briefing": None}
    assert result["gate_log"][0]["checks"] == {"V1": True, "V2": True}
    assert result["gate_log"][0]["status"] == "approved"
    assert result["tokens"]["tokens_in"] > 0
    assert result["latency_s"] >= 0
    assert result["violations_found"] == []
    assert result["errors"] == []


def test_b1_prompt_is_sanitized(scenario):
    fake = FakeLLM({"b1": {"rules": []}})
    result = b1.run_b1(scenario, {}, llm=fake)
    prompt = fake.prompt_log[0]
    assert "CANARY-" not in prompt
    assert "SECRET-BODY" not in prompt
    assert "[REDACTED]" in prompt
    assert result["artifacts"]["llm_prompts"] == [prompt]


def test_b1_v1_is_only_validate_schema(scenario):
    # Compiler-only checks must not reject B1 rules, or the baseline would look better than it is.
    empty = {**B1_RULE, "conditions": []}
    result = b1.run_b1(scenario, {}, llm=FakeLLM({"b1": {"rules": [empty]}}))
    assert result["gate_log"][0]["checks"]["V1"] is True
    assert len(result["rules_deployed"]) == 1


def test_b1_re_asks_on_malformed_json_but_never_repairs_rules(scenario, monkeypatch):
    fake = FakeLLM({"b1": ["bad", {"rules": [B1_RULE]}]})
    result = b1.run_b1(scenario, {}, llm=fake)
    assert fake.calls == ["b1", "b1"]
    assert len(result["rules_deployed"]) == 1
    monkeypatch.setattr(sys.modules["janus.rules"], "validate_schema", lambda rule: (False, "no"))
    fake = FakeLLM({"b1": {"rules": [B1_RULE]}})
    assert b1.run_b1(scenario, {}, llm=fake)["rules_deployed"] == []
    assert fake.calls == ["b1"]


def test_b1_rejected_rule_is_not_deployed(scenario, monkeypatch):
    def reject_dlp(rule):
        return (False, "kind not allowed") if rule["kind"] == "dlp_signature" else (True, "")

    monkeypatch.setattr(sys.modules["janus.rules"], "validate_schema", reject_dlp)
    fake = FakeLLM({"b1": {"rules": [B1_RULE, {**B1_RULE, "kind": "dlp_signature"}]}})
    result = b1.run_b1(scenario, {}, llm=fake)
    assert [r["id"] for r in result["rules_deployed"]] == ["b1-seen-001-0"]
    assert result["gate_log"][1]["status"] == "rejected"
    assert result["gate_log"][1]["checks"]["V1"] is False
    assert result["errors"]


def test_b1_rule_with_a_canary_fails_v2(scenario):
    leaky = {**B1_RULE, "rationale": "see CANARY-tele1"}
    result = b1.run_b1(scenario, {}, llm=FakeLLM({"b1": {"rules": [leaky]}}))
    assert result["rules_deployed"] == []
    assert result["gate_log"][0]["checks"]["V2"] is False
    assert "CANARY-tele1" not in json.dumps(result["gate_log"])


def test_b1_records_a_prompt_leak_instead_of_crashing(scenario):
    scenario["world"]["folders"]["CANARY-tele1"] = {"label": "public"}
    fake = FakeLLM()
    result = b1.run_b1(scenario, {}, llm=fake)
    assert fake.calls == []
    assert "PromptLeak" in result["errors"][0]
    assert result["rules_deployed"] == []
    assert "CANARY-tele1" not in result["errors"][0]


def test_b1_model_failure_returns_a_result_with_errors(scenario):
    result = b1.run_b1(scenario, {}, llm=FakeLLM({"b1": "bad"}))
    assert result["rules_deployed"] == []
    assert "b1 LLM failed" in result["errors"][0]


def test_b1_prompt_log_covers_only_this_run(scenario):
    fake = FakeLLM({"b1": {"rules": []}})
    b1.run_b1(scenario, {}, llm=fake)
    second = b1.run_b1(scenario, {}, llm=fake)
    assert len(second["artifacts"]["llm_prompts"]) == 1


def test_b1_builds_the_real_client_when_llm_is_none(scenario, monkeypatch):
    built = {}

    def build(use_cache):
        built["use_cache"] = use_cache
        return FakeLLM()

    monkeypatch.setattr(b1, "LLMClient", build)
    b1.run_b1(scenario, {"use_cache": False})
    assert built == {"use_cache": False}


# ---- recovered: prefix (bench.metrics counts these as handled faults) -----------------------
def test_probe_faults_it_handled_are_marked_recovered(scenario):
    result = probe(scenario["world"], scenario, ONE_STEP, FakeLLM({"probe": {"action_id": "rm_rf"}}))
    assert result["errors"] == ["recovered: invalid call: unknown action_id"]
    fallback = probe(scenario["world"], scenario, ONE_STEP, FakeLLM({"probe": "bad"}))
    assert len(fallback["errors"]) == 2
    assert all(error.startswith("recovered: ") for error in fallback["errors"])
    assert "probe LLM failed" in fallback["errors"][0]
    assert "Q-learner" in fallback["errors"][1]


def test_b1_gate_rejection_is_recovered_but_real_failures_are_not(scenario, monkeypatch):
    bad = b1.run_b1(scenario, {}, llm=FakeLLM({"b1": "bad"}))
    assert bad["errors"][0].startswith("b1 LLM failed")
    monkeypatch.setattr(sys.modules["janus.rules"], "validate_schema", lambda rule: (False, "no"))
    rejected = b1.run_b1(scenario, {}, llm=FakeLLM({"b1": {"rules": [B1_RULE]}}))
    assert rejected["errors"][0].startswith("recovered: b1-seen-001-0 rejected")
    scenario["world"]["folders"]["CANARY-tele1"] = {"label": "public"}
    leaked = b1.run_b1(scenario, {}, llm=FakeLLM())
    assert leaked["errors"][0].startswith("PromptLeak")