# Section 2c: Diagram notes (draft, Sai Vignesha)

Text for the architecture diagram. Karthik draws the final image in `docs/figures/`.

## Implemented in Milestone 2

- **Rule language (`janus/rules.py`).** A `DefenseRule` is `{id, kind, applies_to, conditions, effect, require_field, addresses_policy, rationale}`. Conditions are ANDed `{field, op, value}`. `FIELDS` holds 13 resolvers that read the action's args or the world. The rule can only use these fields and operators, so it is checkable before it is ever run.
- **One interpreter, three callers.** `rules.enforce` is used by the twin, the verifier (V3 to V5), and the canary endpoint (`gate.evaluate_only`). It never executes or mutates the world, and it fails closed on malformed input.
- **Verifier (`janus/verifier.py`).** Six checks, V1 to V6, on a sanitized scenario. V3 replays the witness on a fresh copy of the world with `policies.apply`.
- **Gate (`janus/gate.py`).** An allow-list: approved rules and the briefing text only. Other input raises `GateViolation`.
- **Pipeline and baselines.** A plain Python state machine (`pipeline.run_p`) with a repair loop of at most 3 rounds, and the B0 adapter (`baselines.run_b0`) that maps B0's four defenses into the same rule language.

## Planned, not built in Milestone 2

- LangGraph orchestration (the state machine stands in for it)
- SQLite memory
- Human approval step
- 3 seeds with bootstrap CIs, and N=5
- Ablations: P-repair, P-memory, P-LLM-probe
- Robustness split

## Changes since Milestone 1

- The state machine in `pipeline.py` replaces LangGraph.
- Rules are typed and closed (fields and operators from `FIELDS`), not free text.
- Verification replays the witness on a fresh twin, instead of checking strings.
- The gate is an allow-list, with a `GateViolation` for anything else.
- The duplicate check (V6) finds exact duplicates only. Contradictory rules are noted in the briefing, not escalated.
- `to.external` uses the same domain rule as the policy oracle, so the rule and the oracle agree.

## Suggested arrows for the diagram

Telemetry → Mirror (redaction, canary check) → Twin → Probe → Violations → Compiler → Rule → Verifier (V1–V6, repair loop) → Gate (`export`) → Deploy → Canary endpoint (`evaluate_only` on the same `enforce`). Only the Gate's outputs leave the sandbox.
