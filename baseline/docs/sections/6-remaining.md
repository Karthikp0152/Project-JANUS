# Section 6: Remaining work (draft)

*Draft note, remove before submission: owners are proposed and still need confirming with each person.*

Milestone 2 built a thin vertical slice: every stage of the Milestone 1 loop runs end to end on the pilot, and the hard gates are measured rather than claimed. The table lists what is left for the final milestone. Required items must be done for the final submission. Optional items strengthen the evaluation if time allows.

## Planned work

| Item | Gap | Planned improvement | Owner | Completion evidence | Required or optional |
|---|---|---|---|---|---|
| Stakeholder feedback follow-up | The Milestone 2 meeting with Puneet has not happened yet | Hold the meeting, apply the feedback and record each change | Pradeep | Meeting notes and a feedback-to-change table | Required |
| Final report | This report is the Milestone 2 draft | Final report with full results and analysis | Pradeep | Final PDF | Required |
| Final presentation and demo | Only a pilot run exists | Slides and a live or recorded `run_p` demo | Mokshitha | Deck and demo recording | Required |
| 3 seeds and bootstrap CIs | One seed (598), so no confidence intervals | Run all splits on three seeds and report mean, standard deviation and 95% bootstrap CIs | Pradeep | `results/` tables with intervals | Required |
| Defense coverage metric | The Milestone 1 metric credits any rule for the right policy and tool, so B1 reaches 1.000 on `heldout` with recall 0. Section 3 notes this | Report a stricter coverage alongside it, counting only rules for violations the system found | Pradeep | Extra column in the tables | Optional |
| LangGraph orchestration | A plain Python state machine stands in | Port `pipeline.py` to LangGraph with checkpoints | Karthik | Graph run trace on the pilot | Optional |
| SQLite memory | No coverage map or rule library across runs | Store rules and coverage across runs, and reuse verified rules | Karthik | P-memory ablation result | Optional |
| Human approval | Not built | Approval step before deploy, off during evaluation | Sai Vignesha | Approval log | Optional |
| Ablations | None run | P-repair, P-memory and P-LLM-probe | Mokshitha | Ablation table | Optional |
| Robustness split | Not built | Secrets in other formats, instruction-like telemetry, malformed events | Vyshanth | Dataset and results | Optional |
| Human rule ratings | None collected | Stakeholder and two peers rate 20 rules from 1 to 5 | Pradeep | Rating sheet and mean score | Optional |
| N = 5 horizon | N = 3 only | Run the pilot at N = 5 | Pradeep | N = 5 results table | Optional |

## From the pilot

| Item | Gap | Planned improvement | Owner | Completion evidence | Required or optional |
|---|---|---|---|---|---|
| Failure cases beyond H3 | Section 5 has one traced case. The H3 gap it describes is fixed: P's `heldout` block rate rose from 0.875 to 1.000 on the re-run | Collect real failing traces from the pilot runs | Sai Vignesha, Mokshitha | Section 5 tables | Required |
| Cold-run latency for every split | The re-runs replayed cached replies, so the latency columns are not real. Cold-run figures exist only from the first run (P about 639 s and B1 about 98 s per held-out scenario), with 12 parallel workers | Re-run all splits with the cache off and report latency per scenario | Pradeep | Tables with cold-run latency | Optional |
| V4 can pass with no variants | 12 of 264 labelled violations, all P4, have no other violating action | Stronger variant generation | Sai Vignesha | Variant counts per policy | Optional |
| Telemetry not applied to P's twin | `run_p` sanitizes telemetry but does not replay it, while B0 does. Pilot telemetry does not change world state | Apply sanitized telemetry to the twin | Karthik | Test with state-changing telemetry | Optional |
| Silent fallbacks undercount recovered faults | `compile_rule` and `write_briefing` fall back without raising, so `recovered_fault_rate` can miss them | Report each fallback and its reason from inside the agents | Mokshitha | Fallbacks visible in `errors` | Optional |
| Probe crash loses findings | The probe returns violations only at the end, so a crash discards what it found | Return partial results on failure | Mokshitha | Test with a mid-run failure | Optional |
| B0 adapter is generous | The mapped rules use folder labels and each world's threshold, while real B0 knows only `payroll`/`hr` folders and a $500 limit | State this in the results, or add a strict B0 variant | Karthik | Note or strict-B0 row in the tables | Optional |
