"""Offline determinism for the test suite: with an API key present in .env, tests must
NOT make live judge/embedding calls (slow, rate-limited, flaky). Live measurement
belongs to the eval runners (evals/run_eval.py, evals/run_external_eval.py)."""
import pytest


@pytest.fixture(autouse=True)
def _offline_isolation(monkeypatch):
    import backend.engine.judge as judge
    import backend.engine.judge_featherless as judge_featherless
    import backend.engine.semantic as semantic

    monkeypatch.setattr(judge, "GEMINI_API_KEY", "")
    monkeypatch.setattr(judge_featherless, "GROQ_API_KEY", "")
    monkeypatch.setattr(semantic, "GEMINI_API_KEY", "")
    # Force the semantic layer to rebuild in TF-IDF mode (deterministic, no network).
    semantic._gemini_vecs = None
    semantic._word_mat = None
    semantic._mode = None
    yield
