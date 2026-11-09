# Section 1: Stakeholder follow-up (draft)

*Draft note, remove before submission: cells marked `[MEETING]` need the notes from the Milestone 2 meeting with Puneet and are left blank on purpose. Everything else is from the Milestone 1 report and the repository.*

## Stakeholder and meetings

| Item | Detail |
|---|---|
| Stakeholder | Puneet Kumar Bokka, author of the Project JANUS proposal and of the runnable baseline (B0) |
| Milestone 1 meeting | 09/27/26: baseline walkthrough, design review, metrics. Scope and success metrics confirmed in writing on 10/02/2026 |
| Milestone 2 meeting | `[MEETING: date, time, medium, who attended]` |
| What we showed | B0 on the example inputs, one end-to-end P run, and the pilot results for B0, B1 and P with the three hard gates (leak, escape, unverified deploy) |
| Agenda and notes | `docs/stakeholder/meeting-agenda.md` and `docs/stakeholder/meeting-notes-template.md` |

## Follow-up on the Milestone 1 feedback

The table traces each point the stakeholder raised in Milestone 1 to what the Milestone 2 system does about it and the evidence.

| Stakeholder feedback (Milestone 1) | What Milestone 2 does | Evidence |
|---|---|---|
| The baseline's `validated` and `payload_escaped` flags are hard-coded, so a reviewer has no reason to trust them | An independent scanner (`janus/scanner.py`) checks every run's artifacts and export for leaks and escapes. It imports nothing from the pipeline, Gate or verifier. Leak, escape and unverified-deploy rates are hard gates | P: 0 leaks, 0 escapes, 0 unverified deploys on all 30 pilot scenarios. B0 and B1 fail the unverified gate by design (no replay verifier) |
| Adding a policy means hand-writing a template and enforcement code, so the baseline cannot grow | An LLM compiler writes typed `DefenseRule`s from the policy and the violation record. Held-out policies H1-H4 have no template fallback | P covers 100% of held-out violations (48 of 48) with recall 1.000. B1 also reaches 1.000 coverage, so this pilot does not show a 20-point gap over B1 (Section 3) |
| The console's Probe buttons send real risky requests to production | The canary step asks `gate.evaluate_only`, which answers allow or deny and never executes the action | `janus/gate.py`, state "Canary" in Section 2 |
| Operators will remove any rule that blocks normal work | Verifier check V5 replays a benign suite, and over-blocking has a target of 5% or less | P over-blocking: 0 of 303, 0 of 296 and 0 of 144 benign actions on seen, held-out and benign. B1 over-blocks 10.2% on seen |
| Keep B0 exactly as it is, or the comparison is not fair | B0's `aswa/` code is untouched. We added an adapter and score it with the same interpreter and scanner | `janus/baselines.py`. The adapter is more generous than the real B0, which we state in Section 3 |
| Keep model costs low and use resources ASU already provides | Agents run on ASU Research Computing models (`muse-glimmer-30b`, `qwen38-27b`) at no cost | Tokens per run are reported (Section 3) |
| An operator may want to approve rules at first | Optional human approval before deploy, off in evaluation runs | **Not built yet.** Planned (Section 6) |
| Confirmed without change: the four-step loop, the Light World / Shadow World / Gate split, the safety invariants, the closed action catalog, the out-of-scope list | Unchanged | Section 2 |

Action items from 09/27, and where they stand:

| Action item | Status |
|---|---|
| Send Section 1 and the Section 6.2 targets for written confirmation | Done: confirmed 10/02/2026 |
| Puneet reviews the benign workflow list for JanusBench | `[MEETING: confirm whether he has reviewed it]` |
| Request ASU Research Computing API access | Done: the pilot ran on the RC gateway |

## What changed since Milestone 1 because of scope

We built a thin vertical slice: every stage of the loop runs end to end on a pilot dataset. LangGraph, SQLite memory, human approval, the robustness split, three seeds with confidence intervals and ablations are planned work, not built (Sections 2 and 6).

## Milestone 2 meeting

| Question we asked | Answer |
|---|---|
| Which results were useful, and which are not yet convincing? | `[MEETING]` |
| Which needs remain unmet (explainable rules, held-out policies, over-blocking, cost)? | `[MEETING]` |
| Are the final deliverables and scope right, with the robustness split, 3 seeds, confidence intervals, ablations and human ratings as remaining work? | `[MEETING]` |
| Are the final success criteria unchanged (gates at 0, held-out coverage 0.80 and 20 points above B1, over-blocking at most 5%)? | `[MEETING]` We note that coverage did not separate B1 from P in the pilot and ask whether to report a stricter coverage next to it |
| Can he rate about 20 sample rules and one full briefing, and by when? | `[MEETING]` |

### Feedback, team response, next action

| Feedback | Team response | Next action |
|---|---|---|
| `[MEETING]` | `[MEETING]` | `[MEETING]` |

Written confirmation requested: `[MEETING: what, and by when]`
