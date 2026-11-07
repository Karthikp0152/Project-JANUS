# Milestone 2 pilot results

Produced by `bench/run_eval.py` on the JanusBench pilot (`data/janusbench/`), single seed 598.

| Item | Value |
|---|---|
| Systems | B0 (frozen baseline via adapter), B1 (one model call), P (agentic pipeline) |
| Splits and sizes | seen 12, held-out 12, benign 6 |
| Models | muse-glimmer-30b (probe, briefing), qwen38-27b (compile, B1), via the ASU RC gateway |
| Probe settings | horizon N=3, 3 episodes per run, temperature per `llm_client.py` |
| Parallelism | 12 workers, so latency is wall time under load |

Reproduce one split:

```bash
python -m bench.run_eval --split seen --system all --n 12 --workers 12 --episodes 3 --out results
```

Files: `<split>_table.md` (results table), `pilot_summary.json` (all metrics). Per-run JSON is large and is not committed.
Limits: pilot sizes, one seed (no confidence intervals), B0 adapter is more generous than real B0, B1 does not probe so its recall is 0 by design.

## Held-out re-run (2026-11-07)

- First run: P and B1 blocked 0.875 of hidden held-out probes. The compiled H3 rule accepted any ticket id, so 36 of 48 H3 probes with unknown ids were allowed.
- Fix: `rules.enforce` now reads the resolved `require_field` value (unknown id resolves to none and is denied), and the verifier adds an unknown-ticket variant (#6).
- Re-run: block rate 1.000 for P and B1, no other metric changed. The re-run replayed cached model replies, so the same compiled rules were scored by the fixed interpreter.
- `heldout_table.md` latency columns come from that cached replay and are not real. Cold-run latency (first run): P 638.59 s, B1 97.65 s per scenario.
- Same caveat for `benign`: P latency 0.09 s per run is cache replay. Use `seen` and `heldout` cold-run latencies.
