# Section 3b: B1 baseline and model settings (draft)

## B1

B1 is a single request to `qwen38-27b`, with no tools. The input is sanitized telemetry, a world summary and the scenario's policy set. The output is a list of `DefenseRule` objects. If the reply is malformed JSON, the shared LLM client re-asks up to 2 times; a well-formed rule is never sent back for repair.

Each rule gets only two checks: V1 (`rules.validate_schema`) and V2 (rule fields only, no canary or secret). Rules that pass are deployed without replay or repair. B1 therefore has no V3-V6 evidence, and its rules count as unverified in the unverified-deploy rate.

## Model settings

| Setting | Value |
|---|---|
| Probe and briefing model | `muse-glimmer-30b` (`RC_MODEL_PROBE`) |
| Compiler and B1 model | `qwen38-27b` (`RC_MODEL_COMPILE`) |
| Temperature | probe 0.3, briefing 0.2, compiler 0, B1 0 |
| Schema retries | up to 2, with the validation error fed back |
| Network retries | up to 4 tries, waiting 1, 2 and 4 seconds, on rate limits and timeouts |
| Cache | On disk in `results/cache/`, keyed on role, model, messages and schema; replayed results keep their original token counts |
| Secret scan | Before every call and every cache replay; `PromptLeak` blocks the call |
| Cost | From `COST_PER_1K_IN` and `COST_PER_1K_OUT`, default 0 for RC; tokens are always reported |

## Results

Cost per run from the cold pilot, the same numbers as Section 3d:

| System | Tokens per run (seen / held-out / benign) | USD | Seconds per run (seen / held-out) |
|---|---|---|---|
| B0 | 0 | 0 | 0 |
| B1 | 2,586 / 3,331 / 4,626 | 0 (RC is free) | 41 / 98 |
| P | 45,791 / 43,898 / 36,359 | 0 (RC is free) | 631 / 639 |

The seconds come from 12 runs in parallel, so a lone run is faster. The lone held-out P run in Section 4 took 592 s of model time.

B1 is cheap: one call per scenario, at about 1/8 to 1/18 of P's tokens. It fails one hard gate by design: its unverified-deploy rate is 1.000 on every split, since no rule is replayed. Its recall is also 0.000 on every split, because it never runs a probe. B1 is still a strong baseline. On held-out policies it matches P on coverage and block rate, both 1.000. On seen policies it falls behind: its rules block 0.933 of hidden variants and over-block 0.102 of benign actions, against P's 1.000 and 0.000.
