"""Keeps test runs from writing evaluation outputs into the committed results/ folder (owner: Pradeep)."""
import pytest


@pytest.fixture(autouse=True)
def _results_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("JANUS_RESULTS_DIR", str(tmp_path / "results"))
