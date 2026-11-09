# Section 5: Failure analysis (draft, Sai Vignesha)

Each failure gives where it happened, the evidence, what we saw and what we think caused it (kept separate), and the fix. Only the H3 case below has a real trace so far; other cases are marked pending.

## Case 1: H3 rule let bogus ticket ids through (verifier, V4)

| Part | Content |
|---|---|
| Where it failed | Verification. V4 passed a rule that the hidden probes later showed was wrong. |
| Evidence | Held-out run (Pradeep): the hidden probes caught **36 of 48** variants that V4 had missed. The missed variants were `update_vendor_bank` actions with a `verification_ticket` that names no ticket in the world. After the fix, on a generated held-out world (`heldout`, seed 598), `make_variants` on the H3 witness yields variants with the unknown id `T-UNKNOWN-0`. |
| Observed | V4 accepted rules that the hidden probes later showed did not block bogus ticket ids (Pradeep's count). We have not yet re-run the pre-fix code on the same world to confirm each case. |
| Suspected cause | V4 only generated ids that exist in the world, so it never tried the unknown-id case. Separately, a "require" rule read the raw argument, so any non-null id counted as verified. Both are our gap, not the probe's. *These are suspicions until the variant set is compared with the hidden probes.* |
| Fix | `make_variants` now adds a variant with an id that names no ticket (`T-UNKNOWN-n`). `enforce` reads the resolved value of `require_field`, so an unknown id resolves to `None` and is denied. Tests: `tests/test_rules.py`, H3 section. |
| How to check | Re-run `heldout`. The 36 cases should now be rejected at V4, and the hidden-probe misses should drop. |

## Case 2: compiler wrote a null comparison (compiler, before the verifier)

| Part | Content |
|---|---|
| Where it failed | Compiler, before the verifier. The rule never reached V1. |
| Evidence | Karthik's `heldout-000` run (cold cache, same run as Section 4): prompt log in the rebuilt RunResult (`janus-demo-heldout-000-demo_run.json`), compile call 4 of 5. Reported by Karthik; the RunResult file has not yet been checked against this text. |
| Observed | The first H3 rule was `deny` when `verification_ticket == null`. `compiler.rule_problem` rejected it with "operator == needs a value". |
| Suspected cause | The model wrote `==` with a null value instead of `is_false`. The compiler's check rejected it, so the rule was never evaluated. The rejection comes from `compiler.rule_problem`; the reason it rejects a null `==` value is not yet confirmed from the code. |
| Fix | The compiler returned the error to the model. The retry used `verification_ticket is_false`, which passed V1–V6 in round 1. Cost: one extra compile call. |
| How to check | Open the RunResult file and confirm call 4 and the rejection message. Then check that the second H3 rule is the one in the verifier's decision. |

## Case 3: pending

*Pending Mokshitha's logs for the other categories (rule over-blocks benign work, the repair loop runs out of rounds, a rule kind does not match the policy). Each gets its own table once a real trace is in hand.*

## Broader limitations

| Limitation | Link to remaining work |
|---|---|
| Restricted task coverage: 9 tools, 8 policies, a toy twin | Robustness split, more policy families |
| Data quality: synthetic worlds, about 12/12/6 pilot scenarios, coarse steps in the unneeded-rule rate | 3 seeds, bootstrap CIs, N=5 |
| V4 can pass with no variants (12 of 264 labelled violations, all P4) | Stronger variant generation; V3 and V5 still apply |
| Dependency failures: RC endpoint, LLM JSON errors, B0 on generated worlds | Retries, cache, fallback templates |
| Cost: tokens per repair round | Ablations (P-repair, P-memory, P-LLM-probe) |
| P3 example uses a literal threshold; compiled rules must take the world's threshold | Compiler sets the value; a threshold field would need a contract change |
