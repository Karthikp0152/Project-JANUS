"""Unit tests for janus.scanner (owner: Pradeep). No network, no LLM."""
from janus.scanner import mask, scan

CANARY = "CANARY-7f3a9c21"


def _clean_artifacts():
    return {
        "twin_dump": '{"users": {"alex": {"role": "employee"}}, "note": "token=[REDACTED]"}',
        "llm_prompts": ["Write one rule for the payment policy."],
        "logs": ["mirror ok", "probe done"],
        "probe_values": ["payment_unapproved", "jane@vendor.com", "payroll"],
    }


def _valid_rule_export():
    rule = {
        "id": "r1",
        "kind": "payment_control",
        "applies_to": "create_payment",
        "conditions": [{"field": "amount", "op": ">", "value": 500}],
        "effect": "require",
        "require_field": "dual_approved",
        "addresses_policy": "P3",
        "rationale": "Payments above the threshold need dual approval.",
    }
    return {"rules": [rule], "briefing": "One rule deployed, none unresolved."}


def test_clean_run_has_no_leaks_or_escapes():
    report = scan(_clean_artifacts(), [CANARY], _valid_rule_export())
    assert report["leaks"] == 0
    assert report["escapes"] == 0
    assert report["details"] == []


def test_canary_in_twin_dump_is_a_leak():
    art = _clean_artifacts()
    art["twin_dump"] += f" password={CANARY}"
    assert scan(art, [CANARY], _valid_rule_export())["leaks"] >= 1


def test_canary_in_prompt_is_a_leak():
    art = _clean_artifacts()
    art["llm_prompts"].append(f"context: {CANARY}")
    assert scan(art, [CANARY], _valid_rule_export())["leaks"] >= 1


def test_canary_in_log_is_a_leak():
    art = _clean_artifacts()
    art["logs"].append(f"debug {CANARY}")
    assert scan(art, [CANARY], _valid_rule_export())["leaks"] >= 1


def test_canary_in_export_is_a_leak():
    export = _valid_rule_export()
    export["briefing"] = f"leaked {CANARY}"
    assert scan(_clean_artifacts(), [CANARY], export)["leaks"] >= 1


def test_secret_shapes_are_flagged_without_a_canary():
    art = _clean_artifacts()
    art["logs"].append("Authorization: Bearer abcdefgh12345678")
    art["logs"].append("key sk-ABCDEFGHIJKLMNOP1234")
    art["logs"].append("password=hunter2hunter2")
    assert scan(art, [], _valid_rule_export())["leaks"] >= 3


def test_redacted_values_are_not_a_leak():
    art = _clean_artifacts()
    art["twin_dump"] = "token=[REDACTED] password: [REDACTED] Bearer [REDACTED]"
    assert scan(art, [CANARY], _valid_rule_export())["leaks"] == 0


def test_details_never_contain_the_full_canary():
    art = _clean_artifacts()
    art["logs"].append(f"debug {CANARY}")
    report = scan(art, [CANARY], _valid_rule_export())
    assert report["details"]
    assert all(CANARY not in line for line in report["details"])
    assert mask(CANARY) == "CA...(15 chars)"


def test_trace_key_in_export_is_an_escape():
    export = _valid_rule_export()
    export["trace"] = [{"step": 1}]
    assert scan(_clean_artifacts(), [CANARY], export)["escapes"] >= 1


def test_args_key_in_export_is_an_escape():
    export = _valid_rule_export()
    export["rules"][0]["args"] = {"amount": 9999}
    assert scan(_clean_artifacts(), [CANARY], export)["escapes"] >= 1


def test_witness_in_export_is_an_escape():
    export = _valid_rule_export()
    export["witness"] = {"violation": {"policy_id": "P3"}, "prefix": []}
    assert scan(_clean_artifacts(), [CANARY], export)["escapes"] >= 2


def test_value_equal_to_probe_content_is_an_escape():
    export = _valid_rule_export()
    export["briefing"] = "payment_unapproved"
    assert scan(_clean_artifacts(), [CANARY], export)["escapes"] >= 1


def test_valid_defense_rule_with_applies_to_is_not_an_escape():
    report = scan(_clean_artifacts(), [CANARY], _valid_rule_export())
    assert report["escapes"] == 0


def test_canary_split_across_log_items_is_not_found_known_limitation():
    art = _clean_artifacts()
    art["logs"] += ["CANARY-7f3", "a9c21"]
    assert scan(art, [CANARY], _valid_rule_export())["leaks"] == 0


def test_missing_artifact_keys_do_not_crash():
    report = scan({}, [CANARY], {})
    assert report["leaks"] == 0 and report["escapes"] == 0
