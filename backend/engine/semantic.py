"""Layer 2 — semantic similarity against the labeled attack corpus.

Two modes, same interface:
  - ONLINE:  Gemini embeddings (gemini-embedding-001), batched, cached on disk
             (data/embeddings_cache.json) so repeated runs don't re-bill.
  - OFFLINE: local TF-IDF (word unigrams + bigrams, sublinear tf, idf) with cosine
             similarity — zero API calls, used automatically when no key is set
             or the API call fails for any reason.

Both modes return the same SemanticHit or None. This layer must never raise.
"""
import hashlib
import json
import math
import re
from pathlib import Path

import numpy as np

from backend.config import GEMINI_API_KEY, GEMINI_EMBED_MODEL, ROOT
from backend.engine.corpus import ATTACK_PAYLOADS
from backend.schemas import SemanticHit

# Chosen from the DEV corpus separation band only (benign max sim 0.247, attack min 1.0):
# 0.35 sits above the benign band and low enough to catch TF-IDF paraphrases. Never tuned
# against the held-out eval set (docs/PROJECT_BLUEPRINT.md §9).
SIMILARITY_THRESHOLD = 0.35

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}|https?://\S+|\S+\.(?:com|net|org|io|ly|xyz|ru|top)\S*", re.IGNORECASE)

_corpus_texts: list[str] | None = None
_corpus_categories: list[str] | None = None
_vectors: np.ndarray | None = None  # normalized rows
_mode: str | None = None  # "gemini" | "tfidf"
_CACHE_PATH = ROOT / "data" / "embeddings_cache.json"


def _tokenize(text: str) -> list[str]:
    toks = [t.lower() for t in _TOKEN_RE.findall(text)]
    return toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]


def _build_tfidf_matrix(texts: list[str]) -> np.ndarray:
    n = len(texts)
    tokenized = [_tokenize(t) for t in texts]
    df: dict[str, int] = {}
    for toks in tokenized:
        for tok in set(toks):
            df[tok] = df.get(tok, 0) + 1
    idf = {tok: math.log((n + 1) / (count + 1)) + 1.0 for tok, count in df.items()}
    vocab = {tok: i for i, tok in enumerate(sorted(idf))}
    mat = np.zeros((n, len(vocab)), dtype=np.float32)
    for r, toks in enumerate(tokenized):
        counts: dict[str, int] = {}
        for tok in toks:
            counts[tok] = counts.get(tok, 0) + 1
        for tok, c in counts.items():
            tf = 1.0 + math.log(c)  # sublinear tf
            mat[r, vocab[tok]] = tf * idf[tok]
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


def _tfidf_vector(text: str, vocab: dict[str, int], idf: dict[str, float]) -> np.ndarray:
    vec = np.zeros(len(vocab), dtype=np.float32)
    counts: dict[str, int] = {}
    for tok in _tokenize(text):
        counts[tok] = counts.get(tok, 0) + 1
    for tok, c in counts.items():
        if tok in vocab:
            vec[vocab[tok]] = (1.0 + math.log(c)) * idf[tok]
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


_tfidf_vocab: dict[str, int] | None = None
_tfidf_idf: dict[str, float] | None = None


def _gemini_embed(texts: list[str]) -> list[list[float]] | None:
    from backend.engine.judge import get_client

    client = get_client()
    if client is None:
        return None
    try:
        from google.genai import types

        res = client.models.embed_content(
            model=GEMINI_EMBED_MODEL,
            contents=texts,
            config=types.EmbedContentConfig(task_type="CLUSTERING"),
        )
        return [list(e.values) for e in res.embeddings]
    except Exception:
        return None


def _load_cache() -> dict:
    if _CACHE_PATH.exists():
        try:
            return json.loads(_CACHE_PATH.read_text())
        except Exception:
            return {}
    return {}


def _ensure_ready() -> bool:
    """Build (or fetch cached) corpus vectors. Idempotent; never raises."""
    global _corpus_texts, _corpus_categories, _vectors, _mode, _tfidf_vocab, _tfidf_idf
    if _vectors is not None:
        return True

    _corpus_texts = [p.text for p in ATTACK_PAYLOADS]
    _corpus_categories = [p.category for p in ATTACK_PAYLOADS]

    if GEMINI_API_KEY:
        key = hashlib.sha256(
            (GEMINI_EMBED_MODEL + "\x00" + "\x00".join(_corpus_texts)).encode()
        ).hexdigest()
        cache = _load_cache()
        if cache.get("key") == key:
            _vectors = np.array(cache["vectors"], dtype=np.float32)
            _mode = "gemini"
            return True
        vecs = _gemini_embed(_corpus_texts)
        if vecs is not None:
            mat = np.array(vecs, dtype=np.float32)
            norms = np.linalg.norm(mat, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            _vectors = mat / norms
            _mode = "gemini"
            try:
                _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                _CACHE_PATH.write_text(
                    json.dumps({"key": key, "vectors": _vectors.tolist()})
                )
            except Exception:
                pass
            return True

    # Offline fallback: TF-IDF over the same corpus
    _vectors = _build_tfidf_matrix(_corpus_texts)
    _tfidf_vocab = {}
    idf: dict[str, float] = {}
    # rebuild vocab+idf from the corpus tokenization (must match _build_tfidf_matrix)
    n = len(_corpus_texts)
    tokenized = [_tokenize(t) for t in _corpus_texts]
    df: dict[str, int] = {}
    for toks in tokenized:
        for tok in set(toks):
            df[tok] = df.get(tok, 0) + 1
    idf = {tok: math.log((n + 1) / (c + 1)) + 1.0 for tok, c in df.items()}
    _tfidf_vocab = {tok: i for i, tok in enumerate(sorted(idf))}
    _tfidf_idf = idf
    _mode = "tfidf"
    return True


def semantic_mode() -> str:
    """Return the active mode without initializing: 'gemini', 'tfidf', or 'uninitialized'."""
    if _mode is None:
        return "gemini" if GEMINI_API_KEY else "tfidf"
    return _mode


def _embed_query(text: str) -> np.ndarray | None:
    if not _ensure_ready():
        return None
    if _mode == "gemini":
        vecs = _gemini_embed([text])
        if vecs is None:
            return None
        v = np.array(vecs[0], dtype=np.float32)
        norm = np.linalg.norm(v)
        return v / norm if norm > 0 else v
    assert _tfidf_vocab is not None and _tfidf_idf is not None
    return _tfidf_vector(text, _tfidf_vocab, _tfidf_idf)


def semantic_scan(text: str) -> SemanticHit | None:
    """Compare text to the attack corpus; return a hit when similarity >= threshold."""
    try:
        if not _ensure_ready():
            return None
        q = _embed_query(text)
        if q is None:
            return None
        sims = _vectors @ q  # type: ignore[operator]
        best = int(np.argmax(sims))
        score = float(sims[best])
        if score < SIMILARITY_THRESHOLD:
            return None
        severity = min(9, 5 + int((score - SIMILARITY_THRESHOLD) * 12))
        return SemanticHit(
            category=_corpus_categories[best],  # type: ignore[index]
            similarity=round(score, 3),
            matched_payload=ATTACK_PAYLOADS[best].name,
            severity=severity,
            mode=_mode or "tfidf",
        )
    except Exception:
        return None
