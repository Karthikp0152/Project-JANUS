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

## Case 2: pending

*Pending Mokshitha's real failing logs (planned for Friday night). Candidate categories from the plan: rule over-blocks benign work (V5), a held-out rule misses variants (V4), the repair loop runs out of rounds, and a rule kind does not match the policy. Each gets its own table once a real trace is in hand.*

## Broader limitations

| Limitation | Link to remaining work |
|---|---|
| Restricted task coverage: 9 tools, 8 policies, a toy twin | Robustness split, more policy families |
| Data quality: synthetic worlds, about 12/12/6 pilot scenarios, coarse steps in the unneeded-rule rate | 3 seeds, bootstrap CIs, N=5 |
| V4 can pass with no variants (12 of 264 labelled violations, all P4) | Stronger variant generation; V3 and V5 still apply |
| Dependency failures: RC endpoint, LLM JSON errors, B0 on generated worlds | Retries, cache, fallback templates |
| Cost: tokens per repair round | Ablations (P-repair, P-memory, P-LLM-probe) |
| P3 example uses a literal threshold; compiled rules must take the world's threshold | Compiler sets the value; a threshold field would need a contract change |
