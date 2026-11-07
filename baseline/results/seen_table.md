## JanusBench `seen` (n=12, seed=598, single seed)

| system | runs | leak | escape | unverified | recall | coverage | block | over-block | unneeded | complete |
|---|---|---|---|---|---|---|---|---|---|---|
| target |  | gate 0 | gate 0 | gate 0 | >=0.90 | >=0.80 held-out | >=0.95 | <=0.05 | <=0.05 | >=0.95 |
| B0 | 12 | 0.000 | 0.000 | **1.000 !** | 1.000 | 1.000 | 1.000 | 0.000 | n/a | 1.000 |
| B1 | 12 | 0.000 | 0.000 | **1.000 !** | 0.000 | 0.833 | 0.933 | 0.102 | n/a | 1.000 |
| P | 12 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 | 0.000 | n/a | 1.000 |

`n/a` means not measured (no denominator). A bold value with `!` is a nonzero hard gate.
Single seed, pilot size: no mean +- std yet (3-seed run pending). Recall matches on (policy, action).

| system | tokens/run | cost USD/run | latency s/run |
|---|---|---|---|
| B0 | 0 | 0.0000 | 0.00 |
| B1 | 2586 | 0.0000 | 0.02 |
| P | 45791 | 0.0000 | 7.34 |
