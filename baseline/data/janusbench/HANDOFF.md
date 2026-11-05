# Vyshanth's completed data contribution

Owner: Vyshanth Buddani. Delivered November 4, 2026 (Arizona time).
Branch: `feat/data-janusbench`.
PR: https://github.com/Karthikp0152/Project-JANUS/pull/2

At Vyshanth's request, the complete assigned implementation and documentation
were finished and committed on November 4 before his absence. No coding or
scheduled future commits are deferred to Thursday, Friday or Saturday. Commit
timestamps reflect the actual work; no multi-day history is claimed.

## Assignment checklist

| Assigned deliverable | Completed evidence |
|---|---|
| WORLD KEYS, examples and tool readers/writers | `janus/world_gen.py` module docstring |
| Nine-tool argument table | `janus/policies.py` module docstring and generated README |
| P1-P4 and H1-H4 oracle | `policies.check`; section 15 definitions, with boundary tests |
| Copy-on-write tool execution | `policies.apply`; all nine effects and purity tested |
| Closed entity-enum action catalog | `policies.catalog`; at most 60 actions in generated worlds |
| Seeded seen/heldout/benign worlds | `world_gen.generate`; isolated RNG and split policies |
| Frozen B0 compatibility | Required fixed entities; actual ASWA execution on all 12 seen worlds |
| Canary planting and sanitizer checks | 1-3 supported-format canaries per world; frozen sanitizer tests |
| Clean benign suites | 20-30 requests per scenario, checked against all eight predicates |
| Reachable ground truth through N=3 | Exact state reduction, earliest steps, enforced-policy filter and cap |
| Hidden variants | Two alternate unsafe requests per label; harness-only |
| Pilot exports and regeneration CLI | `python -m janus.world_gen --export --seed 598` |
| Per-policy sanity table | Generated `README.md`; seen/heldout isolation and zero benign labels |
| Seeded 20% label inspection | `label-review.json`; six scenarios, 46 labels and 18 benign requests |
| Dataset report section | `docs/sections/3a-dataset.md` |
| Contribution evidence | Checkpoint links below; branch and PR available for review |

The label inspection is explicitly AI-assisted: zero errors were found. Human
or stakeholder sign-off cannot be represented as completed by this coding work.
It does not leave any implementation task pending.

## Final validation and dataset counts

From `baseline/`, the full test suite passes **137 tests** and the frozen baseline
command passes without an API key:

```bash
python -m pytest tests -q
python run_baseline.py --input examples/test_unsafe.json
```

Exports reproduce byte-for-byte at the same seed. The review's SHA-256 values
match the exported JSON files. The independent test writer worked from the
contract without reading the implementation; an independent QA reviewer checked
the final code, reduction proof, datasets and report.

| Split | Scenarios | Labels | Benign requests | Hidden probe rows |
|---|---:|---:|---:|---:|
| seen | 12 | 120 | 303 | 240 |
| heldout | 12 | 144 | 296 | 288 |
| benign | 6 | 0 | 144 | 0 |
| Total | 30 | 264 | 743 | 528 |

These are data validation results. Full P/B0/B1 evaluation metrics remain with
the evaluation owner and depend on teammates' real implementations.

## Integration notes

- Sai/Karthik: P1 is external principal AND restricted folder label; H1 is public
  AND confidential/restricted file; H3 rejects null or nonexistent ticket IDs.
  Existing ticket IDs pass H3 regardless of ticket kind or comment count.
- Sai: `check` ignores configured/enforced policies and installed rules. The
  enforcement filter lives in `reachable_violations`. `apply` executes unsafe
  requests too, so verifier/probe callers must enforce before execution.
- Mokshitha: action IDs equal tool names. Use exactly the published argument
  names; principals are user IDs, recipients/payees are email attributes.
- Karthik: every seen world includes the frozen baseline's required identifiers.
  The baseline's own fixed threshold/folder-name predicates remain unchanged;
  the integration adapter must preserve that behavior for a fair comparison.
- Pradeep: consume the three exported JSON files and dataset report section.
  Hidden probes are a flat list with two entries per ground-truth record in
  matching order; repeated probes across records count as repeated rows.
- Hidden variants must not be provided to verifier/compiler prompts. Current
  ground-truth labels all have step-zero witnesses; the N=3 exactness claim does
  not establish difficult multi-step discovery. Audit catalog refresh only
  removes targets, so it cannot introduce labels missing from the initial search.
- All edits are in Vyshanth's owned paths. Shared types, frozen `aswa/`, and
  teammates' modules were preserved. PR review/merge remains the team's workflow.

## Contribution links for Section 7

| Checkpoint | Commit |
|---|---|
| Corrected policy oracle and tool execution | [adcf684](https://github.com/Karthikp0152/Project-JANUS/commit/adcf684) |
| Nine-tool bounded catalog | [b7844a8](https://github.com/Karthikp0152/Project-JANUS/commit/b7844a8) |
| Exact reachable labels and search guard | [8c9682c](https://github.com/Karthikp0152/Project-JANUS/commit/8c9682c) |
| Seeded worlds, canaries and hidden variants | [022c51b](https://github.com/Karthikp0152/Project-JANUS/commit/022c51b) |
| Stable ticket selection during replay | [7fe7f59](https://github.com/Karthikp0152/Project-JANUS/commit/7fe7f59) |
| Audit catalog reachability fix | [30b33ed](https://github.com/Karthikp0152/Project-JANUS/commit/30b33ed) |
| Independent acceptance tests | [1363148](https://github.com/Karthikp0152/Project-JANUS/commit/1363148) |
| Catalog-refresh and CLI regressions | [83551da](https://github.com/Karthikp0152/Project-JANUS/commit/83551da) |
| Pilot exports and regeneration guide | [d9f422f](https://github.com/Karthikp0152/Project-JANUS/commit/d9f422f) |
| Dataset report and inspection evidence | [ded07cb](https://github.com/Karthikp0152/Project-JANUS/commit/ded07cb) |

After merge, use the actual commits present on `origin/main` for the final
contribution record, as COORDINATION requires. Preserve this interaction's full
generative-AI trace for the course disclosure; this handoff is not that full trace.

## Ready-to-share team update

> My complete data contribution is pushed to feat/data-janusbench in PR #2,
> including generate, check, apply, catalog, N=3 ground truth, hidden variants,
> 12/12/6 exports, the sanity table, label-inspection evidence and dataset report.
> P1/H1/H3 match COORDINATION section 15. All 137 tests and frozen B0 pass.
> WORLD KEYS and exact action args are in the module docstrings and dataset README.
> Everything assigned for implementation is committed today before my absence.

This is a prepared handoff message; no group-chat message was sent automatically.
