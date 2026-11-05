# Milestone 2 stakeholder meeting: agenda

- **Stakeholder:** Puneet Kumar Bokka
- **Proposed slot:** Fri Nov 6, 6-7 pm (fallback: Sat Nov 7 morning)
- **Team:** Karthik Ponugoti, Vyshanth Buddani, Sai Vignesha Shesha Shyla, Mokshitha Mohan, Pradeep Krishnamoorthy (lead)
- **Previous meeting:** 09/27/26; scope and metrics confirmed 10/02/2026

## Plan for 30 minutes
| Time (min) | Item |
|---|---|
| 0-3 | Recap of the Milestone 1 agreement and what changed (thin vertical slice; plain Python state machine in place of LangGraph for now) |
| 3-10 | Demo B0: `python run_baseline.py --input examples/test_unsafe.json` |
| 10-17 | Demo P: one end-to-end run (mirror, probe, compile, verify, export, canary check, briefing) |
| 17-22 | First B0 / B1 / P numbers, with the hard gates (leak, escape, unverified deploy); pilot size and single-seed limits |
| 22-30 | Questions below; agree the final deliverables |

## Questions
1. Which results were useful, and which are not yet convincing?
2. Which needs remain unmet (explainable rules, held-out policies, over-blocking, cost)?
3. Are the final deliverables and scope still right: code, JanusBench, report, demo, with the robustness split, 3 seeds, confidence intervals, ablations and human ratings as remaining work?
4. Are the final success criteria unchanged: hard gates at 0, held-out coverage 0.80 and 20 points above B1, over-blocking at most 5%?
5. Can he rate about 20 sample rules and review one full briefing, and by when?
6. Has he reviewed the benign workflow list?

## What we will send before the meeting
- This agenda
- The results plan: datasets (seen, held-out, benign-only pilot), systems (B0, B1, P), metrics and hard gates
