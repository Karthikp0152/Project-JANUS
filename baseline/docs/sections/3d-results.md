# Section 3d: Results (draft)

*Draft note, remove before submission: numbers are from `results/pilot_summary.json` and `results/*_table.md` on `main`. The Section 3a dataset and 3b/3c method text come from Vyshanth, Mokshitha and Sai Vignesha.*

## Setup

| Item | Value |
|---|---|
| Systems | B0 (frozen `aswa` baseline through an adapter), B1 (one `qwen38-27b` call, no tools), P (our agentic pipeline) |
| Data | JanusBench pilot, 30 synthetic scenarios: 12 seen (policies P1-P4), 12 held-out (H1-H4), 6 benign-only |
| Models | `muse-glimmer-30b` (probe, briefing) and `qwen38-27b` (compiler, B1) on the ASU Research Computing gateway |
| Settings | Horizon N = 3, 3 probe episodes per run, seed 598, one seed only |
| Scoring | The harness, not the system, runs the independent scanner and applies the deployed rules to the hidden variants and benign actions with the shared interpreter |

The pilot is deliberately small. It shows whether each mechanism works end to end and where it breaks. It does not support claims of statistical significance (no confidence intervals, one seed).

## Results by split

**Seen policies (12 scenarios)**

| System | Leak | Escape | Unverified deploys | Recall | Coverage | Block rate | Over-blocking | Complete |
|---|---|---|---|---|---|---|---|---|
| Target | 0 | 0 | 0 | ≥ 0.90 | | ≥ 0.95 | ≤ 0.05 | ≥ 0.95 |
| B0 | 0 | 0 | **1.000** | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| B1 | 0 | 0 | **1.000** | 0.000 | 0.833 | 0.933 | 0.102 | 1.000 |
| P | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |

**Held-out policies (12 scenarios)**

| System | Leak | Escape | Unverified deploys | Recall | Coverage | Block rate | Over-blocking | Complete |
|---|---|---|---|---|---|---|---|---|
| Target | 0 | 0 | 0 | ≥ 0.90 | ≥ 0.80 | ≥ 0.95 | ≤ 0.05 | ≥ 0.95 |
| B0 | 0 | 0 | **1.000** | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | 0 | 0 | **1.000** | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| P | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |

**Benign-only (6 scenarios)**

| System | Leak | Escape | Unverified deploys | Over-blocking | Scenarios with an unneeded rule | Rules per run | Complete |
|---|---|---|---|---|---|---|---|
| Target | 0 | 0 | 0 | ≤ 0.05 | ≤ 0.05 | | ≥ 0.95 |
| B0 | 0 | 0 | **1.000** | 0.000 | 1.000 | 4.0 | 1.000 |
| B1 | 0 | 0 | **1.000** | 0.000 | 1.000 | 7.0 | 1.000 |
| P | 0 | 0 | 0 | 0.000 | 0.000 | 0.0 | 1.000 |

Bold means a hard gate is not met. Denominators: 240 hidden variants and 303 benign actions on `seen`; 288 and 296 on `heldout`; 144 benign actions on `benign`. Recall is matched on (policy, action).

## Cost and time

| System | Tokens per run (seen / held-out / benign) | Cost | Seconds per run (seen / held-out) |
|---|---|---|---|
| B0 | 0 | 0 | 0 |
| B1 | 2,586 / 3,331 / 4,626 | 0 (no per-token cost configured) | 41 / 98 |
| P | 45,791 / 43,898 / 36,359 | 0 (no per-token cost configured) | 631 / 639 |

Latency is wall time from the first, cold run with 12 runs in parallel, so a lone run would be faster. The re-runs after the fixes replayed cached model replies, so their latency columns are not real and are not used here. P uses about 8 to 18 times the tokens of B1, depending on the split.

## What the results show

- **The hard gates hold for P.** No leaks, no escapes and no unverified deployments in 30 scenarios. B0 and B1 fail the unverified-deploy gate by construction, because neither has a replay verifier. That gap measures the verifier's existence, not rule quality.
- **P finds everything it should.** Recall is 1.000 on both seen and held-out policies, in every policy (P1-P4 and H1-H4). B1 does not probe, so its recall is 0 by design.
- **P deploys nothing on benign systems.** B0 and B1 deploy 4.0 and 7.0 rules per benign scenario. Over-blocking is 0 for all three on the benign split, so the unneeded rules were harmless in the pilot, but they are exactly the noise an operator would have to review.
- **B1 is a strong single-call baseline.** On held-out policies it matches P on coverage and block rate (both 1.000). **Our target that P beats B1 by 20 points on held-out coverage is not met in this pilot.** Coverage credits any deployed rule for the right policy and tool, so a system that finds nothing can still score 1.000 (B1 does). We kept the Milestone 1 definition and report recall, block rate, over-blocking and the verification gate next to it.
- **Where P is ahead of B1:** the unverified-deploy gate, discovery (recall), and the seen split, where B1 blocks 0.933 of hidden variants against 1.000 and over-blocks 0.102 of benign actions against 0.000.
- **B0 does not generalise.** Its fixed rules cover the seen policies and block nothing on the held-out ones (0.000), as expected from a baseline written for the seen risks. Our B0 adapter is more generous than the real B0, so this flatters B0 on the seen split.

## What the pilot found and fixed

The first held-out run gave P and B1 a block rate of 0.875, below the 0.95 target. The compiled H3 rule required a truthy `verification_ticket`, but the oracle treats an unknown ticket id as missing, so 36 of 48 H3 hidden probes with made-up ids were allowed. The fix (Sai Vignesha, #6) makes `rules.enforce` read the resolved field value and gives the verifier a variant with an unknown ticket id. The re-run, with the same cached model replies, gave 1.000. The failure is in the rule interpreter, not in the models, and it is traced in Section 5.

## Limits

- Pilot size (30 scenarios) and a single seed: no confidence intervals. Three seeds with bootstrap intervals are planned.
- Three probe episodes, not the default five, to fit the time budget.
- The held-out policies share the generator with the seen ones, so held-out here means unseen policy families, not unseen world structure.
- Coverage does not separate B1 from P, as above. A stricter coverage over found violations is listed as optional remaining work (Section 6).
- V4 passes without any variant for 12 of 264 labelled violations, all P4 (Section 5).
- Ground truth and label review were partly AI-assisted (Section 3a).
