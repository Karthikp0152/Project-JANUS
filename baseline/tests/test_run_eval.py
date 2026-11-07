"""Tests for bench.run_eval (owner: Pradeep). Uses fake runners and a fake rule interpreter; no LLM, no network."""
import json

import pytest

from bench import run_eval
from janus import rules


def _result(sc, system, **kw):
    base = {
        "scenario_id": sc["id"], "system": system, "seed": 598, "horizon_n": 3, "violations_found": [],
        "rules_deployed": [], "gate_log": [], "exports": {"rules": [], "briefing": None},
        "artifacts": {"twin_dump": "", "llm_prompts": [], "logs": [], "probe_values": []},
        "tokens": {"tokens_in": 1, "tokens_out": 2}, "cost_usd": 0.0, "latency_s": 0.5, "errors": [],
    }
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def fake_enforce(monkeypatch):
    # deny every action while any rule is installed, so verdicts depend only on rules_deployed
    monkeypatch.setattr(rules, "enforce", lambda deployed, action, world: "deny" if deployed else "allow")


def test_runs_all_systems_on_the_same_scenarios(tmp_path):
    seen_ids = {}

    def runner(system):
        def run(sc, cfg):
            seen_ids.setdefault(system, []).append(sc["id"])
            return _result(sc, system)
        return run

    out = run_eval.evaluate("seen", ["B0", "P"], 3, 598, tmp_path, {s: runner(s) for s in ("B0", "P")})
    assert seen_ids["B0"] == seen_ids["P"] and len(seen_ids["B0"]) == 3
    assert set(out["metrics"]["overall"]) == {"B0", "P"}
    assert (tmp_path / "seen_B0.json").exists() and (tmp_path / "seen_table.md").exists()


def test_a_crashing_run_is_recorded_and_does_not_stop_the_sweep():
    def boom(sc, cfg):
        raise RuntimeError("rc timeout")

    out = run_eval.evaluate("seen", ["P"], 2, 598, None, {"P": boom})
    assert len(out["results"]) == 2
    assert all(r["errors"] and "RuntimeError" in r["errors"][0] for r in out["results"])
    assert out["metrics"]["overall"]["P"]["completion_rate"]["value"] == 0.0


def test_scanner_runs_independently_of_the_system_report(tmp_path):
    def leaky(sc, cfg):
        canary = sc["secrets"][0]
        return _result(sc, "P", artifacts={"twin_dump": f"x {canary}", "llm_prompts": [], "logs": [], "probe_values": []})

    out = run_eval.evaluate("seen", ["P"], 2, 598, None, {"P": leaky})
    assert out["metrics"]["overall"]["P"]["secret_leak_rate"]["value"] == 1.0


def test_post_deploy_verdicts_come_from_rules_enforce():
    def with_rule(sc, cfg):
        return _result(sc, "P", rules_deployed=[{"id": "r", "addresses_policy": "P1", "applies_to": "grant_access"}])

    out = run_eval.evaluate("seen", ["P"], 2, 598, None, {"P": with_rule})
    # the fake interpreter denies everything once a rule is installed: block rate 1, over-blocking 1
    assert out["metrics"]["overall"]["P"]["post_deploy_block_rate"]["value"] == 1.0
    assert out["metrics"]["overall"]["P"]["over_blocking_rate"]["value"] == 1.0


def test_table_flags_nonzero_hard_gates_and_marks_unmeasured_cells(tmp_path):
    def leaky(sc, cfg):
        return _result(sc, "P", artifacts={"twin_dump": f"x {sc['secrets'][0]}", "llm_prompts": [], "logs": [], "probe_values": []})

    out = run_eval.evaluate("seen", ["P"], 1, 598, tmp_path, {"P": leaky})
    table = (tmp_path / "seen_table.md").read_text(encoding="utf-8")
    assert "**1.000 !**" in table
    assert "n/a" in table  # no deployed-rule denominators etc. are shown as not measured, not as 0


def test_workers_give_the_same_results_in_the_same_order():
    def runner(system):
        return lambda sc, cfg: _result(sc, system, cost_usd=float(len(sc["id"])))

    seq = run_eval.evaluate("seen", ["B0", "P"], 4, 598, None, {s: runner(s) for s in ("B0", "P")}, workers=1)
    par = run_eval.evaluate("seen", ["B0", "P"], 4, 598, None, {s: runner(s) for s in ("B0", "P")}, workers=4)
    assert [(r["system"], r["scenario_id"]) for r in par["results"]] == [(r["system"], r["scenario_id"]) for r in seq["results"]]
    assert par["metrics"] == seq["metrics"]


def test_warm_imports_loads_the_runner_modules_before_threads_start():
    import sys

    run_eval._warm_imports()
    for name in ("janus.baselines", "janus.b1", "janus.pipeline", "janus.rules", "aswa.pipeline"):
        assert name in sys.modules


def test_episodes_override_reaches_the_runner():
    seen_cfg = []

    def run(sc, cfg):
        seen_cfg.append(dict(cfg))
        return _result(sc, "P")

    run_eval.evaluate("seen", ["P"], 1, 598, None, {"P": run}, episodes=2)
    run_eval.evaluate("seen", ["P"], 1, 598, None, {"P": run})
    assert seen_cfg[0]["episodes"] == 2 and "episodes" not in seen_cfg[1]


def test_enforce_failures_are_counted_pessimistically(monkeypatch):
    def broken(deployed, action, world):
        raise ValueError("unknown field")

    monkeypatch.setattr(rules, "enforce", broken)

    def with_rule(sc, cfg):
        return _result(sc, "P", rules_deployed=[{"id": "r", "addresses_policy": "P1", "applies_to": "grant_access"}])

    out = run_eval.evaluate("seen", ["P"], 1, 598, None, {"P": with_rule})
    m = out["metrics"]["overall"]["P"]
    assert m["post_deploy_block_rate"]["value"] == 0.0   # hidden probes count as not blocked
    assert m["over_blocking_rate"]["value"] == 1.0       # benign actions count as blocked
    assert m["completion_rate"]["value"] == 0.0          # and the run is marked failed


def test_a_scan_failure_fails_the_hard_gates(monkeypatch):
    def bad_scan(*args, **kwargs):
        raise RuntimeError("bad")

    monkeypatch.setattr(run_eval.scanner, "scan", bad_scan)
    out = run_eval.evaluate("seen", ["P"], 1, 598, None, {"P": lambda sc, cfg: _result(sc, "P")})
    m = out["metrics"]["overall"]["P"]
    assert m["secret_leak_rate"]["value"] == 1.0 and m["payload_escape_rate"]["value"] == 1.0


def test_cli_runs_end_to_end_with_fake_runners(tmp_path, capsys, monkeypatch):
    fakes = {s: (lambda sc, cfg, s=s: _result(sc, s)) for s in run_eval.SYSTEMS}
    monkeypatch.setattr(run_eval, "_default_runners", lambda: fakes)
    code = run_eval.main(["--split", "benign", "--system", "all", "--n", "2", "--out", str(tmp_path)])
    assert code == 0
    assert "JanusBench `benign`" in capsys.readouterr().out
    for system in ("B0", "B1", "P"):
        data = json.loads((tmp_path / f"benign_{system}.json").read_text(encoding="utf-8"))
        assert data["system"] == system and len(data["runs"]) == 2
