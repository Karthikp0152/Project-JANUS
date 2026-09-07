# Project Janus

**Adversarial Shadow-World Architecture (ASWA)**

Project Janus finds weaknesses in a **copy** of your environment, learns how to stop them, and hardens production. Attack behavior never touches the real system. Only validated defenses come back through the Janus Gate.

---

## Explain it simply

1. **Duplicate** build a safe copy of the company system  
2. **Attack** try bad actions only on the copy  
3. **Learn** if a bad action works on the copy, invent a lock  
4. **Deploy** put that lock on the real system  

- **Light World** = real production  
- **Shadow World** = isolated twin  
- **Janus Gate** = one-way door that only lets defenses out  

---

## Quick start (TA reproduction)

```bash
git clone https://github.com/Pun33t-B0kk4/project-janus_aswa.git
cd project-janus_aswa
python -m pip install -r requirements.txt
python run_baseline.py --input examples/test_unsafe.json
```

- **Dependencies:** see `requirements.txt` (fastapi, uvicorn, httpx, pydantic)
- **API keys / env vars:** none required for the baseline
- **Input:** `examples/test_unsafe.json`
- **Output:** printed in the terminal, plus `examples/last_run.json`
- **Screenshot of a successful run:** `examples/baseline_output_screenshot.png`

### Web console (optional demo)

```bash
python run_web.py
```

Open **http://127.0.0.1:8765**

1. Pick an unsafe use case  
2. Click **Run ASWA loop**  
3. Click a **Probe** button to confirm production is hardened  

Local demo token for web API only: `Bearer prod-secret-abc`

### Optional: OpenAI LLM upgrades

The graded baseline does **not** need an API key. For OpenAI LLM features:

1. Copy `.env.example` → `.env`
2. Set `OPENAI_API_KEY` in **`.env`** only
3. Optionally set `OPENAI_BASE_URL` and `OPENAI_MODEL`
4. Run:

```bash
python -m pip install -r requirements.txt
python scripts/test_openai_llm.py
python scripts/demo_llm_aswa.py --input examples/test_unsafe.json
```

OpenAI LLM roles:

- **Adversary:** proposes an N-step shadow plan using only the closed action catalog
- **Learn:** writes operator-facing rationales for each designed defense
- **Briefing:** summarizes Duplicate → Attack → Learn → Deploy for a security operator

---

## Use cases in the console

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

---

## Project layout

```text
aswa/                 Core ASWA loop (RME, ASA, Learn, Janus Gate)
production/           Acme Ops Light World helpers
web/                  Localhost console UI
webapp.py             FastAPI console + production control plane
run_web.py            Start the web demo
run_baseline.py       Offline baseline runner
demo_realworld.py     Scripted live-API demo
scripts/              OpenAI LLM smoke test and demo
examples/             Sample inputs, run notes, baseline screenshot
tests/                Baseline tests
docs/                 Capstone proposal and blueprint
requirements.txt      Python dependencies
```

---

## Requirements

- Python 3.10+
- No cloud API keys for the baseline
- Local demo token for the web API: `Bearer prod-secret-abc`

---

## Tests

```bash
python -c "from tests.test_baseline import *; test_duplicate_redacts_secrets_and_file_bodies(); test_attack_breaks_shadow_but_not_light_world(); test_learn_designs_countermeasures_when_attack_succeeds(); test_deploy_validates_and_mutates_defense_surface_only(); test_loop_order(); print('ok')"
```

Or with pytest if installed:

```bash
python -m pip install pytest
python -m pytest tests/ -q
```

---

## Safety note

This is a **local educational simulator**.

- ASAs use a closed catalog of policy probes inside a toy twin  
- The Gate exports defense rules only  
- It does not implement real exploits or attacks against external systems  

---

## Docs

- Capstone proposal: `docs/CSE598-Project-Janus-Proposal.docx`
- Technical blueprint: `docs/project_janus_aswa_blueprint.pdf`
- Example run notes: `examples/readme.md`
