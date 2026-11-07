# Project Janus

**Adversarial Shadow-World Architecture (ASWA)**

Project Janus finds weaknesses in a **copy** of your environment, learns how to stop them, and hardens production. Attack behavior never touches the real system. Only verified defenses come back through the Janus Gate.

This repository holds the frozen baseline (**B0**, in `aswa/`) and the Milestone 2 agentic system (**P**, in `janus/`), with the JanusBench pilot and an evaluation harness that scores B0, B1 and P the same way.

---

## Explain it simply

1. **Duplicate:** build a safe, sanitized copy of the company system
2. **Attack:** try risky actions only on the copy
3. **Learn:** if a risky action works on the copy, write a rule that stops it
4. **Deploy:** check the rule, then put it on the real system

- **Light World** = real production
- **Shadow World** = isolated twin
- **Janus Gate** = one-way door that only lets verified rules and the operator briefing out

---

## Quick start

```bash
git clone https://github.com/Karthikp0152/Project-JANUS.git
cd Project-JANUS/baseline
python -m pip install -r requirements.txt
```

**Run the tests** (no API key needed):

```bash
python -m pytest tests -q
```

**Run the B0 baseline** (no API key needed):

```bash
python run_baseline.py --input examples/test_unsafe.json
```

Output is printed in the terminal and written to `examples/last_run.json`. A screenshot of a successful run is in `examples/baseline_output_screenshot.png`.

**Run the evaluation:**

```bash
python -m bench.run_eval --split seen --system B0 --n 12 --out /tmp/janus-results
```

B0 needs no key. B1 and P call the ASU Research Computing models, so they need the settings below and make real model calls. A P run on one scenario can take several minutes.

| Option | Values |
|---|---|
| `--split` | `seen`, `heldout` or `benign` |
| `--system` | `B0`, `B1`, `P` or `all` |
| `--n` | Scenarios per split (the pilot uses 12, 12 and 6) |
| `--seed` | Generator seed (default 598) |
| `--workers` | Parallel runs (default 1) |
| `--episodes` | Probe episodes per run (default 5) |
| `--out` | Output folder (default `results/`, which holds the committed pilot results) |

Use `--out` with a scratch folder unless you mean to replace the committed results.

---

## Model settings for B1 and P

1. Copy `.env.example` to `.env`. The `.env` file is gitignored.
2. Fill in the ASU Research Computing values in `.env` only:

| Variable | Value |
|---|---|
| `RC_API_KEY` | Your RC key |
| `RC_BASE_URL` | RC's OpenAI-compatible base URL |
| `RC_MODEL_PROBE` | `muse-glimmer-30b` (probe and briefing) |
| `RC_MODEL_COMPILE` | `qwen38-27b` (compiler and B1) |
| `COST_PER_1K_IN`, `COST_PER_1K_OUT` | Optional; cost is reported as 0 when unset |

Never commit `.env` or print its values. Model replies are cached in `results/cache/`, which is also gitignored.

---

## Systems compared

| System | What it is |
|---|---|
| **B0** | The frozen ASWA baseline: a Q-learner with fixed actions and four fixed defense templates. An adapter runs it on JanusBench and maps its defenses into the shared rule language. Its code is unchanged. |
| **B1** | One call to `qwen38-27b`: no tools, no replay and no repair. |
| **P** | The agentic pipeline: Mirror, Probe, Compile, Verify (V1-V6, up to 3 repair rounds), Export, Deploy, Canary and Brief. |

All three are scored by the same harness, with the independent leak and escape scanner and the same rule interpreter. Pilot results are in [`results/`](results/README.md).

---

## Project layout

```text
aswa/              Frozen B0 baseline (RME, ASA, Learn, Janus Gate). Do not edit.
janus/             Milestone 2 system
  types.py           Shared data contract
  world_gen.py       JanusBench scenario generator
  policies.py        Closed action catalog and policy oracle
  rules.py           Rule language and the one shared interpreter (enforce)
  verifier.py        V1-V6 rule checks
  gate.py            One-way export allow-list and evaluate-only canary check
  llm_client.py      RC client: cache, retries, schema checks, secret scan
  probe_agent.py     LLM probe over the closed catalog, Q-learner fallback
  compiler.py        LLM rule compiler and operator briefing
  pipeline.py        run_p, the P state machine
  baselines.py       run_b0, the B0 adapter
  b1.py              run_b1, the single-call baseline
  scanner.py         Independent leak and escape scanner
bench/             Evaluation harness (run_eval.py) and metrics (metrics.py)
data/janusbench/   Exported pilot scenarios and dataset notes
results/           Pilot result tables and summary
tests/             Tests for every module
docs/              Proposal, blueprint, report sections and stakeholder notes
production/, web/, webapp.py, run_web.py   Baseline web console demo
run_baseline.py    Offline B0 runner
scripts/           OpenAI LLM smoke test and demo for the baseline
examples/          Sample inputs, run notes, baseline screenshot
```

---

## Team

| Person | Area | Main files |
|---|---|---|
| Karthik Ponugoti | Integration | `janus/pipeline.py`, `janus/baselines.py`, `janus/types.py` |
| Vyshanth Buddani | Data | `janus/world_gen.py`, `janus/policies.py`, `data/janusbench/` |
| Sai Vignesha Shesha Shyla | Rules and safety | `janus/rules.py`, `janus/verifier.py`, `janus/gate.py` |
| Mokshitha Mohan | LLM agents | `janus/llm_client.py`, `janus/probe_agent.py`, `janus/compiler.py`, `janus/b1.py` |
| Pradeep Krishnamoorthy | Evaluation and report | `janus/scanner.py`, `bench/`, `results/`, `docs/` |

---

## Status

**Implemented:** every stage of the loop, the three systems, the JanusBench pilot (30 scenarios) and the evaluation harness.

**Planned:** LangGraph orchestration (a plain Python state machine stands in), SQLite memory, a human approval step, a robustness split, three seeds with confidence intervals, ablations, human rule ratings and an N = 5 horizon.

---

## Baseline web console (optional demo)

```bash
python run_web.py
```

Open **http://127.0.0.1:8765**

1. Pick an unsafe use case
2. Click **Run ASWA loop**
3. Click a **Probe** button to confirm production is hardened

Local demo token for the web API only: `Bearer prod-secret-abc`

| Use case | Risk | Description |
|---|---|---|
| Safe IT ticket | Safe | Normal helpdesk comment |
| Contractor payroll access | Unsafe | Outside vendor gets payroll access and salary email |
| Salary file leak | Unsafe | Restricted salary file emailed outside |
| Big wire without approval | Unsafe | Large payment with no dual approval |
| Fake vendor invoice | Unsafe | Payment plus external email fraud pattern |
| Close ticket with no note | Unsafe | Ticket closed without a comment |
| Outsider on HR folder | Unsafe | External identity added to sensitive ACL |
| Internal status email | Safe | Harmless internal email |

The baseline's optional OpenAI features use `OPENAI_API_KEY`, `OPENAI_BASE_URL` and `OPENAI_MODEL` in `.env`. See `scripts/test_openai_llm.py` and `scripts/demo_llm_aswa.py`. They are switched off when B0 is evaluated.

---

## Requirements

- Python 3.10+
- No API key for B0 or the tests
- RC settings in `.env` for B1 and P

---

## Safety note

This is a **local educational simulator** on synthetic data.

- Probing uses a closed catalog of nine simulator tools inside a toy twin
- Secrets are redacted before any model sees the data, and every prompt is scanned
- The Gate exports verified defense rules and the briefing only
- It does not implement real exploits or attacks against external systems

---

## Docs

- Capstone proposal: `docs/CSE598-Project-Janus-Proposal.docx`
- Technical blueprint: `docs/project_janus_aswa_blueprint.pdf`
- Dataset notes: `data/janusbench/README.md`
- Pilot results: `results/README.md`
- Example run notes: `examples/readme.md`
