# Section 7: Repository and contributions (draft)

*Draft note, remove before submission: commit counts are `git shortlog -sne --no-merges` on `main` at the time of writing. Re-run it before submitting and update the counts. Links use the repository `github.com/Karthikp0152/Project-JANUS`.*

Repository: https://github.com/Karthikp0152/Project-JANUS (code in `baseline/`). Every teammate has commits on `main`, and all work reached `main` through a pull request or a reviewed branch merge.

## Contribution table

| Member | Role | What they built | Commits on `main` | Pull requests | Key commits |
|---|---|---|---|---|---|
| Karthik Ponugoti | Repo owner, orchestration | Data contract and stubs, `run_p` state machine, `run_b0` adapter, README, Sections 2 and 6 and the architecture diagram | 12 (13 including one commit under his second GitHub identity `Karthikp0152`) | #4, #7, #9 | [e3d3173](https://github.com/Karthikp0152/Project-JANUS/commit/e3d3173), [1a349e3](https://github.com/Karthikp0152/Project-JANUS/commit/1a349e3), [12de588](https://github.com/Karthikp0152/Project-JANUS/commit/12de588) |
| Vyshanth Buddani | Data | JanusBench world generator, policy oracle (P1-P4 seen, H1-H4 held-out), pilot dataset and label review, tests, Section 3a | 11 | #2 | [adcf684](https://github.com/Karthikp0152/Project-JANUS/commit/adcf684), [022c51b](https://github.com/Karthikp0152/Project-JANUS/commit/022c51b), [d9f422f](https://github.com/Karthikp0152/Project-JANUS/commit/d9f422f) |
| Sai Vignesha Shesha Shyla | Rules and safety | Rule language and shared interpreter, verifier V1-V6, Gate allow-list, review fixes (never-raise validation, H3 fix, oracle-matching lookups), Sections 3c and 5 | 12 | #5, #6, #10 | [e668e07](https://github.com/Karthikp0152/Project-JANUS/commit/e668e07), [c877ff1](https://github.com/Karthikp0152/Project-JANUS/commit/c877ff1), [94b3e49](https://github.com/Karthikp0152/Project-JANUS/commit/94b3e49) |
| Mokshitha Mohan | LLM agents | RC client with cache, retries and secret scan, probe agent, defense compiler and briefing, B1 baseline, tests, Sections 2b, 3b and 4 | 12 | #3, #8 | [5351612](https://github.com/Karthikp0152/Project-JANUS/commit/5351612), [cdd4578](https://github.com/Karthikp0152/Project-JANUS/commit/cdd4578), [59302a5](https://github.com/Karthikp0152/Project-JANUS/commit/59302a5) |
| Pradeep Krishnamoorthy | Evaluation, report, integration | Independent leak and escape scanner, metrics, evaluation harness (parallel runs), the pilot results, test isolation fix, reviewed and merged every pull request, Sections 1, 3d and 7, stakeholder liaison | 14 | Branch merges `feat/eval-scanner`, `feat/eval-completion`, `feat/eval-parallel`, plus review of #2-#10 | [413a267](https://github.com/Karthikp0152/Project-JANUS/commit/413a267), [2972243](https://github.com/Karthikp0152/Project-JANUS/commit/2972243), [56dd0a8](https://github.com/Karthikp0152/Project-JANUS/commit/56dd0a8) |

Merge commits for the pull requests are in the `main` history; `git log --merges --oneline` lists them.

## Commits that are not team contributions

`main` also holds 6 commits authored by the stakeholder, Puneet Kumar Bokka (5-6 September 2026). They are the original Project JANUS baseline (B0, the web console and the proposal) that our team received. The `aswa/` code is unchanged from that baseline. A further commit on 4 October added the baseline to this repository.

## Process

- One branch per area, then a pull request into `main`. The integration lead (Pradeep) reviewed each pull request in a separate worktree, merged it with main, ran the full test suite and the B0 check, and had an independent review agent look for defects before merging.
- Merge order followed dependencies: contract, then data and agents, then rules and pipeline, then evaluation.
- Review findings were fixed before merging or through a follow-up pull request, for example the interpreter fix behind the held-out block rate (#6, #10) and the recovered-fault convention (#8).
- No force-pushes, and the baseline `aswa/` package was never edited.

## Reading the commit history

- Commit timing is uneven. Vyshanth's 11 commits are all dated 4 November, and Sai Vignesha's follow-up work is concentrated on 7 November. Contribution is therefore best read from the files and pull requests above rather than from commit dates.
- Some contributors used a personal email address on commits, so GitHub may not link them to the ASU account. The commit authors in `git shortlog` identify them.

## Generative-AI use

The course requires disclosing the full generative-AI interaction trace. It is in the appendix of this report: one section per team member.
