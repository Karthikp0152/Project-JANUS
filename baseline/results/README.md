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
