# Examples

## Inputs

- `test_unsafe.json` graded unsafe telemetry case
- `test_safe.json` benign telemetry case

## Run

```bash
python run_baseline.py --input examples/test_unsafe.json
```

OpenAI LLM demo (requires `OPENAI_API_KEY` in `.env`):

```bash
python scripts/test_openai_llm.py
python scripts/demo_llm_aswa.py --input examples/test_unsafe.json
```

## Outputs

Running the baseline writes:

- console trace
- `last_run.json` (gitignored local artifact)

`baseline_output_screenshot.png` is the captured baseline console output used in the proposal.

OpenAI LLM demo writes `last_llm_run.json` (gitignored local artifact).
