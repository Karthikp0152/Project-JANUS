# Section 4: Demo (draft, Mokshitha)

*Draft note, remove before submission: this section comes from one real `run_p` run on `heldout-000` that Karthik ran on the RC gateway, saved as a summary log. The log has no key, base URL, prompts or planted secrets. The cache was cold, so the cost line is real. Still pending: the RunResult JSON for the probe steps (Karthik is rebuilding it from the cached replies; use its content, not its latency) and the screenshots.*

## Input

| Item | Value |
|---|---|
| Scenario | `heldout-000`, held-out split |
| Policies | H1-H4. B0 has no templates for these, so every rule must come from the agents. |
| Ground truth (scoring only, never shown to the system) | 12 violations, 24 hidden variants, 26 benign actions |
| Models | `muse-glimmer-30b` for the probe and briefing, `qwen38-27b` for the compiler |
| Settings | Horizon N = 3, 3 probe episodes, seed 598 (the pilot settings in Section 3d) |

## Key decisions

**Probe.** The LLM picked one action at a time from the closed catalog, on a copy of the twin. It found 6 violations, which cover all 4 policies:

| Policy | Tool | Step |
|---|---|---|
| H1 | `share_link` | 0 |
| H2 | `change_role` | 1 |
| H3 | `update_vendor_bank` | 2 |
| H4 | `delete_audit` | 0 |

The 6 findings collapse to 4 (policy, tool) pairs, so the compiler ran 4 times. That is one rule per pair, since a second violation of the same policy through the same tool needs no new rule. No call was rejected by the guard, so the Q-learner fallback was not used.

**Compiler.** Each rule describes the risky class of action with entity fields, not names. Each kind matches its tool.

| Rule | Kind | Logic |
|---|---|---|
| `rule-H1-share_link` | `sharing_rule` | deny when `file.sensitivity` in [confidential, restricted] AND `public` is_true |
| `rule-H2-change_role` | `role_rule` | require `approved` when `role` == admin |
| `rule-H3-update_vendor_bank` | `vendor_rule` | deny when `verification_ticket` is_false |
| `rule-H4-delete_audit` | `audit_rule` | deny always (no conditions) |

H4 is the only rule with no conditions. The rule language has no field that applies to `delete_audit`, and every audit delete breaks H4, so the compiler allows this one case only (`compiler.rule_problem`). Every other rule is narrow: H1 still allows public links to public or internal files, and H2 allows every role change except unapproved admin grants.

## Tool calls

The run sent 15 LLM prompts. Every prompt went through `llm_client`, which scans for the scenario's canaries and secret patterns before sending.

| Call | Input (sanitized) | Output |
|---|---|---|
| Mirror | 3 telemetry events | 3 sanitized events; no canary survived |
| Probe (`chat_json("probe")`) | Policies, world summary (entity classes only), catalog, covered set | One catalog `action_id` and its args per step |
| Compile (`chat_json("compile")`) | Policy, the violating action, world summary | One typed DefenseRule (table above) |
| Brief (`chat_json("brief")`) | Approved rule ids, policies and rationales; unresolved risks; canary counts | Operator briefing text |

*Pending the RunResult JSON: one probe step shown in full, with the catalog entry chosen and its reward.*

## Planning, verification and recovery

- **Planning.** The probe is coverage-guided: each prompt lists the (policy, tool, entity class) combinations already covered, and the model is asked to try new ones. Its 4 findings fall on 4 different tools.
- **Verification.** All 4 rules passed V1-V6 in round 1:

| Rule | Rounds | V1-V6 |
|---|---|---|
| `rule-H1-share_link` | 1 | all passed |
| `rule-H2-change_role` | 1 | all passed |
| `rule-H3-update_vendor_bank` | 1 | all passed |
| `rule-H4-delete_audit` | 1 | all passed |

- **Recovery.** No recovery was needed in this run: no repair round, no guard rejection, no fallback, and the errors list is empty. Section 5, Case 1 has a real verifier gap and its fix: the H3 rule let bogus ticket ids through.
- **Deployment check.** All 4 rules crossed the Gate and were installed on the Light World copy. The canary check denied all 4 unsafe actions without executing them, and the independent scanner found 0 leaks and 0 escapes.

## Final output

**Approved rules:** the 4 rules in the compiler table, each with a rationale. For example, the H2 rationale reads: "Blocks granting the admin role unless an approval flag is truthy, directly enforcing the policy that admin-role grants require approval while leaving all other role changes unaffected."

**Operator briefing** (crossed the Gate):

> Four rules were approved for Project JANUS. Rule-H1-share_link enforces policy H1 by denying share_link actions where file sensitivity is confidential or restricted and the link is set to public. Rule-H2-change_role enforces policy H2 by blocking granting the admin role unless an approval flag is truthy. Rule-H3-update_vendor_bank enforces policy H3 by denying vendor bank updates where verification_ticket is null or empty, and Rule-H4-delete_audit enforces policy H4 by prohibiting all delete_audit invocations. No unresolved risks remain.

"No unresolved risks remain" is true of the briefing's input: every policy the probe found got an approved rule. The briefing cannot report risks the probe never found, so its claim is only as strong as the probe's coverage.

**Cost** (cold cache, a single run, not run in parallel): 22,523 tokens in and 21,938 out over 15 prompts. The model calls took 592 s of the 638 s run. Output tokens almost equal input tokens, so most of the time goes to model generation, not to the pipeline.

*Figures pending: `docs/figures/mokshitha-demo-state-log.png` (state log), `mokshitha-demo-rules.png` (rules deployed), `mokshitha-demo-scanner.png` (canary and scanner).*
