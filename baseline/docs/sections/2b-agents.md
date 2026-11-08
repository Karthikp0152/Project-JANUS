# Section 2b: Agent roles and tools (draft)

| Component | Model | Decides | Tools |
|---|---|---|---|
| Probe agent | `muse-glimmer-30b` | Next `(action_id, args)` from the closed catalog | `list_catalog`, `shadow_execute`, `shadow_state`, `policy_check` |
| Defense compiler | `qwen38-27b` | Narrowest `DefenseRule` per violation | `retrieve_policy`, `list_rules`, `validate_rule`, `dry_run` |
| Briefing (`compiler.write_briefing`) | `muse-glimmer-30b` | Operator text from approved rules | none |
| B1 | `qwen38-27b` | One-shot rule set | none |

Tool names are the Milestone 1 design names (Section 3.2-3.7). Milestone 2 does not build all of them. The agents do not call tools themselves: `probe_agent` and `compiler` make the `policies.*` and `rules.*` calls. `shadow_state` is a world summary in the prompt, `retrieve_policy` is the policy text in the prompt, and `validate_rule` is `rules.validate_schema`. `list_rules` and `dry_run` are not implemented in the compiler; rule replay happens in the verifier.

## How the agents work

- **Probe agent.** At each step the model picks one action from `policies.catalog(twin)`. A guard checks the id, the argument names and each value against the catalog. Valid actions run on a copy of the twin, and `policies.check` reports any violation. Reward is +10 for a new violation, -0.1 per step and -5 for an invalid call.
- **Coverage planning.** The prompt lists the policy, tool and entity-class combinations already tried, and asks the model to prefer new ones.
- **Probe fallback.** If the model gives no usable reply (3 malformed replies in a row, or a failed call), a Q-learner finishes the probe (20 episodes, epsilon 0.3, alpha 0.3, gamma 0.9). It uses the method from `aswa/asa.py`, adapted to work on any world's catalog.
- **Defense compiler.** The model writes one `DefenseRule`. Its JSON schema is built from `rules.FIELDS` and the allowed kinds and operators, so it cannot name a field that does not exist. The prompt holds the policy, the single violation and a world summary, with no witness prefix or trace. On repair rounds, the verifier's reason is added to the prompt.
- **Compiler fallback.** Seen policies (P1-P4) fall back to `TEMPLATE_RULES`. Held-out policies (H1-H4) have no template, so `compile_rule` raises `CompileError`.
- **Briefing.** The input is limited to approved rule ids, policies and rationales, unresolved risks (policy and text), canary counts and the error count. Other input keys are dropped before the prompt is built.

## Error handling

| Failure | Handling |
|---|---|
| Malformed JSON or failed call | Malformed replies are retried up to 2 times with the error fed back; then Q-learner (probe), or `TEMPLATE_RULES` or `CompileError` (compiler) |
| Unknown catalog id or arg | Guard rejects, reward -5 |
| Rate limit, timeout or server error (HTTP 408, 429, 500, 502, 503, 504) | Exponential backoff: 1, 2 and 4 seconds, 4 tries in total |
| `PromptLeak` | Call blocked, run aborted, recorded in `errors` |
| Invalid rule schema or shape | `compiler.rule_problem` rejects it before the verifier sees it; retry with the reason, then fallback as above. Verifier rejections go through repair rounds, then escalate. |

Handled faults are recorded in `errors` with a `recovered: ` prefix, so `bench.metrics` counts the run as complete and adds it to the recovered-fault rate. `PromptLeak` is never prefixed.

**Observed in the pilot (30 scenarios).** P completed every run and recorded no handled fault: no Q-learner fallback, no template and no `CompileError`. Compiler retries happen inside `compile_rule` and are not written to `errors`. Section 4 shows a real one: the first H3 rule used `verification_ticket == null`, `rule_problem` rejected it ("operator == needs a value"), and the retry used `is_false`. B1 had at least one rule rejected by V1 or V2 in 8 of 12 seen runs and in all 6 benign runs; the rejected rules were dropped and the rest deployed.
