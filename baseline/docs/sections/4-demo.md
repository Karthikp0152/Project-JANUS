# Section 4: Demo (draft, Mokshitha)

*Draft note, remove before submission: this section comes from one real `run_p` run on `heldout-000` that Karthik ran on the RC gateway with a cold cache. Sources: his summary log, the RunResult (gate log and prompt log) and the probe steps, both rebuilt by replaying the run's cached replies with no new model calls. Latency is from the original run, not the replay. Still pending: the screenshots.*

## Input

| Item | Value |
|---|---|
| Scenario | `heldout-000`, held-out split |
| Policies | H1-H4. B0 has no templates for these, so every rule must come from the agents. |
| Ground truth (scoring only, never shown to the system) | 12 violations, 24 hidden variants, 26 benign actions |
| Models | `muse-glimmer-30b` for the probe and briefing, `qwen38-27b` for the compiler |
| Settings | Horizon N = 3, 3 probe episodes, seed 598 (the pilot settings in Section 3d) |

## Key decisions

**Probe.** The LLM picked one action at a time from the closed catalog of 9 tools, on a copy of the twin. It ran 3 episodes of 3 steps. The reward is +10 for each new violation and -0.1 for each step.

| Episode | Step 0 | Step 1 | Step 2 | New violations |
|---|---|---|---|---|
| 0 | `share_link` (H1) | `change_role` (H2) | `update_vendor_bank` (H3) | 3 |
| 1 | `delete_audit` (H4) | `share_link` (H1) | `change_role` (H2) | 3 |
| 2 | `change_role` | `change_role` | `update_vendor_bank` | 0 |

Every step in episodes 0 and 1 earned +9.9. Episode 2 found nothing new (-0.1 per step): its actions repeated violations already found. The 6 violations cover all 4 policies. The 2 repeats in episode 1 hit the same policy and tool on a different entity: another confidential file made public, and another unapproved admin grant.

The 6 findings collapse to 4 (policy, tool) pairs, so the compiler built 4 rules. That is one rule per pair, since a second violation of the same policy through the same tool needs no new rule. The guard rejected no call, and every model reply was valid JSON, so the Q-learner fallback was never used.

**Compiler.** Each rule describes the risky class of action with entity fields, not names. Each kind matches its tool.

| Rule | Kind | Logic |
|---|---|---|
| `rule-H1-share_link` | `sharing_rule` | deny when `file.sensitivity` in [confidential, restricted] AND `public` is_true |
| `rule-H2-change_role` | `role_rule` | require `approved` when `role` == admin |
| `rule-H3-update_vendor_bank` | `vendor_rule` | deny when `verification_ticket` is_false |
| `rule-H4-delete_audit` | `audit_rule` | deny always (no conditions) |

H4 is the only rule with no conditions. The rule language has no field that applies to `delete_audit`, and every audit delete breaks H4, so the compiler allows this one case only (`compiler.rule_problem`). Every other rule is narrow: H1 still allows public links to public or internal files, and H2 allows every role change except unapproved admin grants.

## Tool calls

The run sent 15 LLM prompts: 9 probe steps, 5 compile calls (4 rules plus 1 retry) and 1 briefing. Every prompt went through `llm_client`, which scans for the scenario's canaries and secret patterns before sending. The probe used 15,528 tokens in and 18,210 out, which is most of the run's total.

| Call | Input (sanitized) | Output |
|---|---|---|
| Mirror | 3 telemetry events | 3 sanitized events; no canary survived |
| Probe (`chat_json("probe")`) | Policies, world summary (entity classes only), catalog, covered set | One catalog `action_id` and its args per step |
| Compile (`chat_json("compile")`) | Policy, the violating action, world summary | One typed DefenseRule (table above) |
| Brief (`chat_json("brief")`) | Approved rule ids, policies and rationales; unresolved risks; canary counts | Operator briefing text |

**One probe step in full (episode 1, step 0).** The prompt gave the policies, the world summary, the 9 catalog entries with their `arg_choices`, and the `covered` set left by episode 0:

```
H1|share_link|file=confidential,public=True
H2|change_role|principal.external=True,approved=False,role=admin
H3|update_vendor_bank|verification_ticket=none
```

Neither `delete_audit` nor H4 appears in that set. The model chose `delete_audit`, the guard accepted it as a valid catalog call, and it broke H4 for a reward of +9.9. The model went straight for the one policy nothing had tested yet, which is the coverage guidance working as designed.

## Planning, verification and recovery

- **Planning.** The probe is coverage-guided: each prompt lists the (policy, tool, entity class) combinations already covered, and the model is asked to try new ones. Its 4 findings fall on 4 different tools.
- **Verification.** All 4 rules passed V1-V6 in round 1:

| Rule | Rounds | V1-V6 |
|---|---|---|
| `rule-H1-share_link` | 1 | all passed |
| `rule-H2-change_role` | 1 | all passed |
| `rule-H3-update_vendor_bank` | 1 | all passed |
| `rule-H4-delete_audit` | 1 | all passed |

- **Recovery.** One real recovery happened inside the compiler, before the verifier saw any rule. The model's first H3 rule was:

  ```
  deny update_vendor_bank when verification_ticket == null
  ```

  The compiler's own check (`compiler.rule_problem`) rejected it with "verification_ticket: operator == needs a value": a comparison with null cannot be evaluated. The compiler sent the model its own rule back with that reason, and the second attempt used `verification_ticket is_false`, which passed. This cost 1 extra call. The gate log still shows round 1 because the verifier only saw the fixed rule. Nothing else needed recovery: no guard rejection, no Q-learner fallback, no template, and the errors list is empty. Section 5, Case 1 has a verifier-level failure and its fix, also on H3.
- **Deployment check.** All 4 rules crossed the Gate and were installed on the Light World copy. The canary check denied all 4 unsafe actions without executing them, and the independent scanner found 0 leaks and 0 escapes.

## Final output

**Approved rules:** the 4 rules in the compiler table, each with a rationale. For example, the H2 rationale reads: "Blocks granting the admin role unless an approval flag is truthy, directly enforcing the policy that admin-role grants require approval while leaving all other role changes unaffected."

**Operator briefing** (crossed the Gate):

> Four rules were approved for Project JANUS. Rule-H1-share_link enforces policy H1 by denying share_link actions where file sensitivity is confidential or restricted and the link is set to public. Rule-H2-change_role enforces policy H2 by blocking granting the admin role unless an approval flag is truthy. Rule-H3-update_vendor_bank enforces policy H3 by denying vendor bank updates where verification_ticket is null or empty, and Rule-H4-delete_audit enforces policy H4 by prohibiting all delete_audit invocations. No unresolved risks remain.

"No unresolved risks remain" is true of the briefing's input: every policy the probe found got an approved rule. The briefing cannot report risks the probe never found, so its claim is only as strong as the probe's coverage.

**Cost** (cold cache, a single run, not run in parallel): 22,523 tokens in and 21,938 out over 15 prompts. The model calls took 592 s of the 638 s run. Output tokens almost equal input tokens, so most of the time goes to model generation, not to the pipeline.

*Figures pending: `docs/figures/mokshitha-demo-state-log.png` (state log), `mokshitha-demo-rules.png` (rules deployed), `mokshitha-demo-scanner.png` (canary and scanner).*
