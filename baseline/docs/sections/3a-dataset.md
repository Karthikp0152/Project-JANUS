# Section 3a: JanusBench pilot dataset

JanusBench is a synthetic benchmark generated in the repository from seed 598,
using the frozen ASWA demonstration and its payroll-access, salary-email,
unapproved-payment and ticket-closing examples as starting cases. Each scenario
contains a production-world dictionary, configured policies, telemetry, planted
canaries, reachable policy violations, benign requests and harness-only hidden
probes. The task is to discover policy violations within a shadow-world horizon
of N=3 and compile defenses that stop unsafe requests while allowing normal work.
Worlds vary across 8-30 users, 6-10 folders, four folder labels and payment
thresholds from 300 to 2000. Names, file contents and email attributes are synthetic.

The exported pilot contains 30 scenarios: 12 seen scenarios configure P1-P4 only,
12 held-out scenarios configure H1-H4 only, and six benign-only scenarios configure
and already enforce all eight policies. These splits contain 120, 144 and zero
distinct ground-truth violation records, respectively. There are 743 benign
requests (303/296/144) and 528 hidden probe rows (240/288/0). Each world includes
20-30 distinct benign requests, and each violation has two alternative hidden
probes; probes shared across labels remain repeated rows. These are the exact
exported counts, not claims of completed P/B0/B1 evaluation. The evaluation owner
must report the number of scenarios and labels actually used in system runs.

P1 follows the final shared definition: a principal must be external and the
folder label must be restricted. Internal contractors do not violate P1, and
folder names alone have no effect. Payroll and HR folders are always labeled
restricted. H1 covers public links to both confidential and restricted files.
H3 rejects both null verification tickets and IDs absent from the world's ticket
dictionary. All policy texts, checks and tests use these corrected definitions.

The nine-tool catalog uses bounded deterministic entity enums, with at most 60
fully expanded actions per generated world. Ground truth enumerates this catalog
through N=3 and keeps the earliest zero-based step for each distinct
(policy_id, action_id, args) key. A naive enumeration would have up to
60 + 60^2 + 60^3 = 219,660 action sequences per world. The implementation reduces
equivalent states using ticket-comment presence and existing audit IDs, discards
stuttering transitions, and prunes branches after recording a violation. This is
exact for the implemented tools: comments only remove P4 violations, audit
deletion only removes H4 targets, and no other mutation changes an oracle input.
Catalog refresh cannot introduce new entity choices after a transition. The
search raises a scenario-specific error rather than returning partial labels
after 200,000 deduplicated-state action evaluations. An independent test compares
the optimized labels with naive enumeration through depth three.

All current reachable violations have direct step-zero witnesses. This pilot
therefore tests the specified N=3 reachability labels but does not establish
performance on violations that first become possible after a multi-step prefix.
Ground truth is exhaustive over published catalog enums, rather than every
possible argument value or every entity in the larger world. Extra users/files,
new amounts and nonexistent verification-ticket IDs supply hidden evaluation
variants. The verifier must not receive those hidden probes. Audit variants use
other existing entries; those IDs are also available in the public catalog.

Each scenario plants one to three random CANARY strings in telemetry using the
frozen sanitizer's supported password=... or token-key formats. Automated checks
confirm that every planted value is removed by `aswa.rme.sanitize_value` and that
benign requests satisfy all eight oracle predicates. Determinism is checked
across repeated calls, independent processes/hash seeds and byte-identical
exports. Every seen world retains B0's fixed entity IDs; tests run frozen ASWA on
all 12 seen worlds through a test-only adapter. The production B0 adapter remains
the integration owner's responsibility, and its unchanged folder-name/500-dollar
logic is a known mismatch with the generated policy labels and thresholds.

Quality-control evidence is recorded in `data/janusbench/label-review.json` for
six seeded scenarios (20%): benign-003, benign-002, seen-003, heldout-009,
heldout-011 and heldout-002. An independent Codex QA agent inspected all 46
ground-truth records in those scenarios and their first three benign requests
(18 total), finding zero label errors and requiring no label fixes.
The inspection is AI-assisted; human sign-off by
Vyshanth/the team and stakeholder review of benign workflows remain pending.
The report must not describe this record as a completed human annotation review.

The held-out split tests unseen policy families, the benign split measures
over-blocking, and canaries support independent leak detection. Limitations
include the small pilot, one seed, a toy twin, bounded enums, repeated hidden
probes and labels produced by the same oracle that defines the policies. No
robustness split, three-seed study, confidence intervals or human rule-usefulness
ratings have been completed by this data contribution. The larger Milestone 1
design (40 seen, 30 held-out, 15 benign and 15 robustness scenarios) remains future
work. Regenerate the pilot from `baseline/` using
`python -m janus.world_gen --export --seed 598`.
