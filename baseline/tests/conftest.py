"""Keeps test runs from writing evaluation outputs into the committed results/ folder (owner: Pradeep)."""
import pytest


@pytest.fixture(autouse=True)
def _results_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("JANUS_RESULTS_DIR", str(tmp_path / "results"))


@pytest.fixture(autouse=True)
def _no_real_model_calls(monkeypatch):
    """A real RC key in the local env file must never reach a test. Empty values (not deleted ones) stop
    llm_client's load_dotenv(override=False) from filling the key back in. Tests that need a model
    inject FakeLLM or their own transport."""
    for name in ("RC_API_KEY", "RC_BASE_URL", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, "")
