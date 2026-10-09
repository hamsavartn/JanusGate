"""Layer 2 — semantic similarity against the labeled attack corpus.

Two channels, combined by max:
  - WORD channel: word unigrams + bigrams, TF-IDF + cosine (precise on literal overlap)
  - CHAR channel: character 3-5-gram TF-IDF + cosine (robust to paraphrase, leetspeak,
    separator tricks)

Both channels operate on normalized text (NFKC + zero-width removal + light leet
un-mapping in the char channel). Online mode (GEMINI_API_KEY) replaces both with Gemini
embeddings + a disk cache. This layer must never raise.
"""
import hashlib
import json
import math
import re
import unicodedata
from pathlib import Path

import numpy as np

from backend.config import GEMINI_API_KEY, GEMINI_EMBED_MODEL, ROOT
from backend.engine.corpus import ATTACK_PAYLOADS
from backend.schemas import SemanticHit

# Chosen from the DEV corpus separation band only (benign max sim 0.247, attack min 1.0):
# 0.35 sits above the benign band and low enough to catch TF-IDF paraphrases. Never tuned
# against the held-out eval set (docs/PROJECT_BLUEPRINT.md §9).
SIMILARITY_THRESHOLD = 0.35

_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\xad]")
_LEET_RE = re.compile(r"[01@$]|\$")
_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                           "@": "a", "$": "s", "!": "i"})
_WORD_RE = re.compile(r"[a-z0-9]{2,}|https?://\S+|\S+\.(?:com|net|org|io|ly|xyz|ru|top)\S*")


def normalize_text(text: str, leet: bool = False) -> str:
    t = _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", text)).lower()
    if leet:
        t = t.translate(_LEET_MAP)
    return t


def _word_tokens(text: str) -> list[str]:
    toks = _WORD_RE.findall(normalize_text(text))
    return toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]


def _char_tokens(text: str) -> list[str]:
    t = normalize_text(text, leet=True)
    t = re.sub(r"[^a-z0-9]+", " ", t)
    grams: list[str] = []
    for word in t.split():
        padded = f" {word} "
        for n in (3, 4, 5):
            grams.extend(padded[i:i + n] for i in range(len(padded) - n + 1))
    return grams


def _tfidf_vectorize(token_lists: list[list[str]]) -> tuple[np.ndarray, dict[str, int], dict[str, float]]:
    n = len(token_lists)
    df: dict[str, int] = {}
    for toks in token_lists:
        for tok in set(toks):
            df[tok] = df.get(tok, 0) + 1
    idf = {tok: math.log((n + 1) / (c + 1)) + 1.0 for tok, c in df.items()}
    vocab = {tok: i for i, tok in enumerate(sorted(idf))}
    mat = np.zeros((n, len(vocab)), dtype=np.float32)
    for r, toks in enumerate(token_lists):
        counts: dict[str, int] = {}
        for tok in toks:
            counts[tok] = counts.get(tok, 0) + 1
        for tok, c in counts.items():
            mat[r, vocab[tok]] = (1.0 + math.log(c)) * idf[tok]
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms, vocab, idf


def _project(tokens: list[str], vocab: dict[str, int], idf: dict[str, float]) -> np.ndarray:
    vec = np.zeros(len(vocab), dtype=np.float32)
    counts: dict[str, int] = {}
    for tok in tokens:
        counts[tok] = counts.get(tok, 0) + 1
    for tok, c in counts.items():
        if tok in vocab:
            vec[vocab[tok]] = (1.0 + math.log(c)) * idf[tok]
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


_corpus_texts: list[str] | None = None
_corpus_categories: list[str] | None = None
_word_mat: np.ndarray | None = None
_char_mat: np.ndarray | None = None
_word_vocab = _word_idf = _char_vocab = _char_idf = None
_gemini_vecs: np.ndarray | None = None
_mode: str | None = None  # "gemini" | "tfidf"
_CACHE_PATH = ROOT / "data" / "embeddings_cache.json"


def _gemini_embed(texts: list[str]) -> list[list[float]] | None:
    from backend.engine.judge import get_client

    if get_client() is None:  # no key, or quota circuit breaker tripped
        return None
    try:
        from google.genai import types

        res = get_client().models.embed_content(
            model=GEMINI_EMBED_MODEL,
            contents=texts,
            config=types.EmbedContentConfig(task_type="CLUSTERING"),
        )
        return [list(e.values) for e in res.embeddings]
    except Exception:
        return None


def _ensure_ready() -> bool:
    """Build (or fetch cached) corpus vectors. Idempotent; never raises.

    TF-IDF matrices are ALWAYS built (cheap, local) so a live gemini query-embed
    failure can fall back to TF-IDF without losing the semantic layer entirely.
    """
    global _corpus_texts, _corpus_categories, _word_mat, _char_mat, _gemini_vecs
    global _word_vocab, _word_idf, _char_vocab, _char_idf, _mode
    if _word_mat is not None:
        return True

    _corpus_texts = [p.text for p in ATTACK_PAYLOADS]
    _corpus_categories = [p.category for p in ATTACK_PAYLOADS]

    # Local fallback channel — always ready.
    word_lists = [_word_tokens(t) for t in _corpus_texts]
    char_lists = [_char_tokens(t) for t in _corpus_texts]
    _word_mat, _word_vocab, _word_idf = _tfidf_vectorize(word_lists)
    _char_mat, _char_vocab, _char_idf = _tfidf_vectorize(char_lists)

    if GEMINI_API_KEY:
        key = hashlib.sha256(
            (GEMINI_EMBED_MODEL + "\x00" + "\x00".join(_corpus_texts)).encode()
        ).hexdigest()
        cache = _load_cache()
        if cache.get("key") == key:
            _gemini_vecs = np.array(cache["vectors"], dtype=np.float32)
            _mode = "gemini"
            return True
        vecs = _gemini_embed(_corpus_texts)
        if vecs is not None:
            mat = np.array(vecs, dtype=np.float32)
            norms = np.linalg.norm(mat, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            _gemini_vecs = mat / norms
            _mode = "gemini"
            try:
                _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                _CACHE_PATH.write_text(json.dumps({"key": key, "vectors": _gemini_vecs.tolist()}))
            except Exception:
                pass
            return True

    _mode = "tfidf"
    return True


def _load_cache() -> dict:
    if _CACHE_PATH.exists():
        try:
            return json.loads(_CACHE_PATH.read_text())
        except Exception:
            return {}
    return {}


def semantic_mode() -> str:
    return _mode if _mode is not None else ("gemini" if GEMINI_API_KEY else "tfidf")


def semantic_scan(text: str) -> SemanticHit | None:
    """Compare text to the attack corpus across channels; hit when sim >= threshold."""
    try:
        if not _ensure_ready():
            return None

        if _mode == "gemini" and _gemini_vecs is not None:
            vecs = _gemini_embed([text])
            if vecs is None:
                # Live embed failed (quota/rate limit) — fall back to TF-IDF channels.
                sims = np.maximum(
                    _word_mat @ _project(_word_tokens(text), _word_vocab, _word_idf),
                    _char_mat @ _project(_char_tokens(text), _char_vocab, _char_idf),
                )
                fallback = True
            else:
                v = np.array(vecs[0], dtype=np.float32)
                norm = np.linalg.norm(v)
                if norm > 0:
                    v = v / norm
                sims = _gemini_vecs @ v
                fallback = False
        else:
            word_sim = _word_mat @ _project(_word_tokens(text), _word_vocab, _word_idf) \
                if _word_mat is not None else np.zeros(1)
            char_sim = _char_mat @ _project(_char_tokens(text), _char_vocab, _char_idf) \
                if _char_mat is not None else np.zeros(1)
            sims = np.maximum(word_sim, char_sim)
            fallback = False

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
            mode=("tfidf-fallback" if fallback else (_mode or "tfidf")),
        )
    except Exception:
        return None
