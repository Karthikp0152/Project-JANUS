# Section 3c: Verifier and Gate (draft)

Every proposed rule must pass six checks before it can be deployed. The verifier (`janus/verifier.py`) runs the checks on a sanitized copy of the scenario, so no file contents or secrets are visible to it. A rule is approved only if all six hold. Otherwise it is rejected with one structured reason, which goes back to the compiler for a repair round (at most 3 rounds, then the violation is escalated). The gate (`janus/gate.py`) is the only way out: `export()` passes through only approved rules and the briefing text, and raises `GateViolation` on anything else, including trace fields or a canary in the text. `evaluate_only()` answers the canary question by calling the same `rules.enforce` as the twin, and never runs the action.

| Check | What it proves | Failure reason (example) |
|---|---|---|
| V1 | Rule is well-formed: string id and rationale, known kind, tool, policy id, effect and operators; `require_field` is an argument of the rule's tool and set only for `require` | `V1 failed: rule ex-x is malformed` |
| V2 | Rule is pure: only schema keys, no trace, action or probe fields, no scenario secret in its text | `V2 failed: rule contains a scenario secret` |
| V3 | Replaying the witness on a fresh copy of the world, then the violating action, is denied with the rule installed | `V3 failed: witness P3-1 still allowed; world dual-approval threshold is 1500` |
| V4 | Every other action that violates the same policy is also denied. Variants come from the world's own entities, plus derived values: payment amounts above the threshold, and (for H3) a verification ticket id that names no ticket | `V4 failed: variant H3-variant-2 not blocked` |
| V5 | Every benign action in the scenario is still allowed with the rule installed | `V5 failed: blocks benign action payment-07` |
| V6 | Rule is not a duplicate of an installed rule (same tool, conditions and effect) | `V6 failed: duplicates installed rule ex-firewall-p1` |

Reasons contain action and rule ids only, never arguments, file contents or secret values, because the compiler prompt receives them. The one exception is the P3 threshold in the V3 reason, which is a world setting and not an argument or secret, so the compiler can repair the amount.

`verify()` never raises. Unusable input (no world, malformed secrets, a non-mapping rule) returns a rejected decision.

**H3 gap found in the held-out run.** An H3 rule that checks the raw `verification_ticket` argument let bogus ticket ids through, because V4 only tried ids that exist. The hidden probes caught 36 of the 48 variants that V4 missed. Two changes fix this: V4 now builds a variant with an id that names no ticket, and `require_field` is read from the resolved value, so an unknown id resolves to `None` and is denied. The held-out re-run will show whether this closes the gap.

**Known limitation: V4 can pass vacuously.** If a violation has no other violating action in the world, V4 has nothing to test and passes. The pilot has 12 of 264 labelled violations like this, all P4 (close ticket without comment). For those, V3 is still the check that holds the rule to the witness, and V5 still tests for over-blocking.

*Pilot numbers are added once the held-out re-run finishes.*
