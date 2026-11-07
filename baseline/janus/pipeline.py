"""P, the JANUS agentic pipeline. Owner: Karthik Ponugoti.

A plain Python state machine (LangGraph is planned): Mirror, Probe, Compile, Verify, Export, Deploy,
Canary, Brief. Each state appends to `artifacts["logs"]`. LLMs run only in Probe, Compile and Brief;
sanitizing, verifying and exporting are deterministic.

Safety properties kept here:
- A planted canary surviving the mirror aborts the run before any LLM client exists (12.4).
- The probe receives the mirrored scenario with no answer key, hidden variants or benign suite.
- The verifier receives the mirrored scenario too, without the answer key or hidden variants, because its
  reasons feed back into compiler prompts.
- The compiler sees the sanitized world and one Violation record, never a witness or trace (11.2).
- Witnesses never reach logs or exports; logs hold counts and ids only.
- Rules cross the Gate before deployment. The briefing is written afterwards and crosses separately, so
  it can report canary results, and a failure while briefing cannot undo deployed rules.
- If the Gate fails for any reason, nothing is deployed and the risks are reported as unresolved.
- A rule that fails its canary check counts as an unresolved risk, even though it stays deployed.
- A failure keeps what the run's finished states did, so the scanner still sees its prompts and logs, and
  the operator still gets a briefing built from ids and policy references, with no LLM involved. The probe
  returns its findings only at the end, so a probe that raises loses the violations it had found.

Every agent gets a client bound to this scenario's id and canaries, so the secret scan runs on every prompt.

`errors` follows bench.metrics: a fault the run recovered from starts with "recovered:" (a compile failure
followed by an approved rule, probe faults the probe handled, a briefing replaced by the fallback). Real
failures have no prefix (PromptLeak, a surviving canary, a Gate refusal, a crash, a canary check that raises,
compile failures on a violation that ended up escalated). Escalation itself is not an error, and neither is
a rule that answers its canary check with "allow": it is reported as a risk and measured by the block rate.

Violations of policies the scenario does not configure, or already enforces, are ignored: `policies.check`
deliberately ignores enforcement (11.3), and acting on them would deploy unneeded rules on benign worlds.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from aswa.rme import sanitize_value

from janus import compiler, gate, probe_agent, verifier
from janus.llm_client import LLMClient, PromptLeak
from janus.types import (
    DEFAULT_HORIZON_N,
    Action,
    DefenseRule,
    GateDecision,
    PipelineConfig,
    Policy,
    RunResult,
    Scenario,
    TokenUse,
    Violation,
    Witness,
)

DEFAULT_REPAIR_ROUNDS = 3
RECOVERED = "recovered: "


@dataclass
class _Run:
    """Everything one run accumulates."""

    secrets: list[str]
    logs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    gate_log: list[GateDecision] = field(default_factory=list)
    approved: list[DefenseRule] = field(default_factory=list)
    unresolved: list[Violation] = field(default_factory=list)

    def log(self, state: str, message: str) -> None:
        self.logs.append(f"{state}: {message}")

    def record(self, text: str) -> None:
        for secret in sorted(filter(None, self.secrets), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        self.errors.append(text[:300])

    def error(self, state: str, exc: BaseException, *, recovered: bool = False) -> None:
        self.record(f"{RECOVERED}{state}: {type(exc).__name__}: {exc}" if recovered else f"{state}: {type(exc).__name__}: {exc}")


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _mirror(scenario: Scenario) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    twin = sanitize_value(deepcopy(scenario["world"]))
    for meta in twin.get("files", {}).values():
        meta["contents"] = "[SANITIZED]"
    return twin, sanitize_value(deepcopy(scenario["telemetry"]))


def _without_answers(scenario: Scenario, **changes: Any) -> Scenario:
    return Scenario(**{**scenario, "ground_truth": [], "hidden_variants": [], **changes})


def _to_action(violation: Violation) -> Action:
    # In the closed catalog an action_id is the tool name (janus.policies.catalog).
    return Action(action_id=violation["action_id"], tool=violation["action_id"], args=violation["args"])


def _actionable(violations: list[Violation], scenario: Scenario) -> list[Violation]:
    """One violation per (policy, action), for configured policies the world does not already enforce."""
    configured = {policy["id"] for policy in scenario["policies"]} - set(scenario["enforced_policy_ids"])
    unique: dict[tuple[str, str], Violation] = {}
    for violation in violations:
        if violation["policy_id"] in configured:
            unique.setdefault((violation["policy_id"], violation["action_id"]), violation)
    return list(unique.values())


def _witness_for(violation: Violation, witnesses: list[Witness]) -> Witness:
    for witness in witnesses:
        if witness["violation"] == violation:
            return witness
    return Witness(violation=violation, prefix=[])


def _probe_values(violations: list[Violation], witnesses: list[Witness]) -> list[str]:
    values: set[str] = set()
    actions = [_to_action(violation) for violation in violations]
    for witness in witnesses:
        actions.append(_to_action(witness["violation"]))
        actions.extend(witness["prefix"])
    for action in actions:
        values.add(str(action["action_id"]))
        values.update(str(value) for value in action["args"].values() if value is not None)
    return sorted(values)


def _compile_and_verify(
    violation: Violation,
    policy: Policy,
    witness: Witness,
    twin: dict[str, Any],
    verifier_view: Scenario,
    max_rounds: int,
    llm: Any,
    run: _Run,
) -> None:
    """Compile, verify and repair one violation, ending approved or escalated."""
    twin_view = {"world": twin, "violation": violation}
    feedback: str | None = None
    decision: GateDecision | None = None
    failures: list[Exception] = []
    for round_number in range(1, max_rounds + 1):
        try:
            rule = compiler.compile_rule(violation, policy, twin_view, feedback, llm)
            decision = verifier.verify(rule, witness, verifier_view, run.approved)
        except PromptLeak:
            for failure in failures:
                run.error("Compile/Verify", failure)
            raise
        except Exception as exc:
            failures.append(exc)  # keeps `feedback`: the last verifier reason is still the useful one
            continue
        decision["rounds"] = round_number
        if decision["status"] == "approved":
            for failure in failures:
                run.error("Compile/Verify", failure, recovered=True)
            run.approved.append(rule)
            run.gate_log.append(decision)
            run.log("Verify", f"{rule['id']} approved in round {round_number}")
            return
        feedback = decision["reason"]
        run.log("Verify", f"{rule['id']} rejected in round {round_number}")

    for failure in failures:
        run.error("Compile/Verify", failure)
    if decision is None:  # no attempt produced a rule, but the risk must still reach the operator
        decision = GateDecision(
            rule_id=f"unresolved-{violation['policy_id']}-{violation['action_id']}", status="rejected",
            checks={f"V{i}": False for i in range(1, 7)}, reason="No rule could be compiled", rounds=max_rounds,
        )
    decision["status"] = "escalated"
    decision["rounds"] = max_rounds
    run.gate_log.append(decision)
    run.unresolved.append(violation)
    run.log("Verify", f"{decision['rule_id']} escalated after {max_rounds} rounds")


def _canary(deployed: list[DefenseRule], violations: list[Violation], twin: dict[str, Any], run: _Run) -> dict[str, int]:
    """Ask the evaluate-only endpoint about each unsafe action; nothing is executed."""
    denied = 0
    for violation in violations:
        try:
            verdict = gate.evaluate_only(deployed, _to_action(violation), twin)
        except Exception as exc:
            run.error("Canary", exc)
            verdict = "unknown"
        if verdict == "deny":
            denied += 1
        elif violation not in run.unresolved:
            run.unresolved.append(violation)
    run.log("Canary", f"{denied}/{len(violations)} unsafe actions denied")
    return {"denied": denied, "checked": len(violations)}


def _summary(scenario: Scenario, deployed: list[DefenseRule], canary: dict[str, int], run: _Run) -> dict[str, Any]:
    """Rule ids and policy text only: the briefing input never holds traces (M1 Section 3.2)."""
    text = {policy["id"]: policy["text"] for policy in scenario["policies"]}
    return {
        "scenario_id": scenario["id"],
        "approved_rules": [
            {"id": rule["id"], "policy": rule["addresses_policy"], "rationale": rule["rationale"]}
            for rule in deployed
        ],
        "unresolved_risks": [
            {"policy": violation["policy_id"], "text": text.get(violation["policy_id"], "")}
            for violation in run.unresolved
        ],
        "canary": canary,
        "errors": sum(not error.startswith(RECOVERED) for error in run.errors),
    }


def _fallback_briefing(summary: dict[str, Any]) -> str:
    rules = ", ".join(item["id"] for item in summary["approved_rules"]) or "none"
    risks = ", ".join(item["policy"] for item in summary["unresolved_risks"]) or "none"
    return f"Deployed rules: {rules}. Unresolved risks: {risks}."


def _with_caveat(text: str, summary: dict[str, Any]) -> str:
    """Added here because write_briefing may return its own text, which can read as an all-clear."""
    if summary["errors"]:
        return f"{text} The run recorded {summary['errors']} failure(s), so this list may be incomplete."
    return text


def _export_briefing(text: str, deployed: list[DefenseRule], scenario: Scenario, run: _Run) -> dict[str, Any] | None:
    try:
        return gate.export(run.gate_log, deployed, text, canaries=scenario["secrets"])
    except Exception as exc:
        run.error("Brief", exc)
        return None


def _brief(
    summary: dict[str, Any],
    deployed: list[DefenseRule],
    llm: Any,
    scenario: Scenario,
    run: _Run,
) -> dict[str, Any]:
    """Send the written briefing through the Gate, or the fallback if that fails; rules stay deployed either way."""
    write_failure: Exception | None = None
    written: str | None = None
    try:
        written = compiler.write_briefing(summary, llm)
    except PromptLeak as exc:  # a real failure, but this is the last LLM call, so nothing is left to abort
        run.error("Brief", exc)
    except Exception as exc:
        write_failure = exc
    if written:
        exported = _export_briefing(_with_caveat(written, summary), deployed, scenario, run)
        if exported is not None:
            return exported
    exported = _export_briefing(_with_caveat(_fallback_briefing(summary), summary), deployed, scenario, run)
    if write_failure is not None:
        run.error("Brief", write_failure, recovered=exported is not None)
    return exported if exported is not None else {"rules": deployed, "briefing": None}


def _refuse_export(violations: list[Violation], run: _Run) -> None:
    """Rules the Gate would not export are not deployed, so their risks stay open for the operator."""
    for decision in run.gate_log:
        if decision["status"] == "approved":
            decision["status"] = "escalated"
            decision["reason"] = "The Gate refused the export"
    run.unresolved = list(violations)
    run.approved = []


def _close_aborted(scenario: Scenario, out: dict[str, Any], run: _Run) -> None:
    """After a failure: no approved record for rules that never deployed, and the operator still hears of the risks."""
    if not out["deployed"]:
        _refuse_export(out["violations"], run)
    if out["exports"].get("briefing"):
        return
    try:
        summary = _summary(scenario, out["deployed"], {"denied": 0, "checked": 0}, run)
        text = _with_caveat(_fallback_briefing(summary), summary)
        exported = _export_briefing(text, out["deployed"], scenario, run)
    except Exception as exc:
        run.error("Aborted", exc)
        return
    if exported is not None:
        out["exports"] = exported


def _no_outputs() -> dict[str, Any]:
    return {"violations": [], "deployed": [], "exports": {"rules": [], "briefing": None}, "probe_values": []}


def _execute(
    scenario: Scenario, twin: dict[str, Any], telemetry: list, cfg: PipelineConfig, llm: Any, run: _Run, out: dict
) -> None:
    """Probe through Brief. Fills `out` as each state finishes, so a later failure keeps earlier results."""
    view = _without_answers(scenario, world=twin, telemetry=telemetry, benign_actions=[])
    verifier_view = _without_answers(scenario, world=twin, telemetry=telemetry)
    try:
        probed = probe_agent.probe(twin, view, cfg, llm)
        found, witnesses = probed["violations"], probed["witnesses"]
        for text in probed["errors"]:
            run.record(f"{RECOVERED}Probe: {text}")  # the probe returned, so it handled these itself
    except PromptLeak:
        raise
    except Exception as exc:
        run.error("Probe", exc)
        found, witnesses = [], []
    out["violations"] = _actionable(found, scenario)
    out["probe_values"] = _probe_values(found, witnesses)
    run.log("Probe", f"{len(found)} violations, {len(out['violations'])} to act on")

    policies = {policy["id"]: policy for policy in scenario["policies"]}
    max_rounds = cfg.get("max_repair_rounds", DEFAULT_REPAIR_ROUNDS)
    for violation in out["violations"]:
        witness = _witness_for(violation, witnesses)
        _compile_and_verify(
            violation, policies[violation["policy_id"]], witness, twin, verifier_view, max_rounds, llm, run
        )

    try:
        exported = gate.export(run.gate_log, run.approved, None, canaries=scenario["secrets"])
    except Exception as exc:
        run.error("Export", exc)
        _refuse_export(out["violations"], run)
        exported = {"rules": [], "briefing": None}
    out["exports"] = exported
    out["deployed"] = list(exported["rules"])
    run.log("Export", f"{len(out['deployed'])} rules crossed the Gate")
    run.log("Deploy", f"{len(out['deployed'])} rules installed on the Light World copy")

    canary = _canary(out["deployed"], out["violations"], twin, run)
    summary = _summary(scenario, out["deployed"], canary, run)
    out["exports"] = _brief(summary, out["deployed"], llm, scenario, run)
    run.log("Brief", "briefing written" if out["exports"]["briefing"] else "no briefing crossed the Gate")


def run_p(scenario: Scenario, cfg: PipelineConfig, llm: Any = None) -> RunResult:
    started = time.perf_counter()
    run = _Run(secrets=list(scenario["secrets"]))
    twin, telemetry = _mirror(scenario)
    twin_dump = json.dumps({"world": twin, "telemetry": telemetry}, sort_keys=True, default=str, ensure_ascii=False)
    run.log("Mirror", f"{len(scenario['telemetry'])} telemetry events sanitized")

    out = _no_outputs()
    usage_before: dict[str, float] = dict(llm.usage) if llm is not None else {}
    prompts_before = len(llm.prompt_log) if llm is not None else 0
    # Searched as raw strings, because serializing escapes quotes and backslashes in a secret.
    mirrored = list(_strings([twin, telemetry]))
    if any(secret and secret in text for secret in scenario["secrets"] for text in mirrored):
        run.errors.append("Mirror: a planted canary survived sanitizing; aborted before any LLM call")
        _close_aborted(scenario, out, run)
    else:
        try:
            if llm is None:
                llm = LLMClient(use_cache=cfg.get("use_cache", True))
            bound = llm.bind(scenario["id"], scenario["secrets"])
            _execute(scenario, twin, telemetry, cfg, bound, run, out)
        except Exception as exc:  # includes PromptLeak; the run stops but keeps what it already did
            run.error("Aborted", exc)
            _close_aborted(scenario, out, run)

    usage = llm.usage if llm is not None else {}
    return RunResult(
        scenario_id=scenario["id"], system="P", seed=cfg.get("seed", scenario["seed"]),
        horizon_n=cfg.get("horizon_n", DEFAULT_HORIZON_N), violations_found=out["violations"],
        rules_deployed=out["deployed"], gate_log=run.gate_log, exports=out["exports"],
        artifacts={
            "twin_dump": twin_dump,
            "llm_prompts": list(llm.prompt_log[prompts_before:]) if llm is not None else [],
            "logs": run.logs,
            "probe_values": out["probe_values"],
        },
        tokens=TokenUse(
            tokens_in=int(usage.get("tokens_in", 0) - usage_before.get("tokens_in", 0)),
            tokens_out=int(usage.get("tokens_out", 0) - usage_before.get("tokens_out", 0)),
        ),
        cost_usd=usage.get("cost_usd", 0.0) - usage_before.get("cost_usd", 0.0),
        latency_s=time.perf_counter() - started,
        errors=run.errors,
    )
