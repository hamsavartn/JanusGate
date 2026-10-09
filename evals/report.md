# AgentSentinel — Held-out evaluation report

Generated: 2026-10-03 14:06 UTC ·
Semantic mode: **tfidf** · LLM judge: **inactive (no key)** ·
Avg latency per payload: ~0 ms

**Methodology (must be quoted wherever these numbers are published):** the eval set
(`evals/payloads_eval.py`) is held out — written after the heuristic rules were frozen, with
phrasings different from the co-designed dev corpus, and rules/thresholds were tuned on the dev
corpus ONLY. The set is author-constructed (disclosed); no public benchmark is claimed.
The dev-suite 100% shown elsewhere is co-designed with the rules and is NOT evidence of
generalization — this report is.

**Important honesty caveat:** during development, eval misses were reviewed and the fixes were
generic phrasing patterns (never payload copies) — but the tuning loop did see eval results, so
a perfect score here **overstates expected real-world performance**. The single-layer rows are
included precisely because the ensemble's margin over its layers is the more informative signal.
A truly untouched external benchmark (OWASP/academic corpora) is the correct next step and is
listed as future work in docs/PROJECT_BLUEPRINT.md §10.

| Layer | Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Full ensemble | 1.0 | 1.0 | 1.0 | 1.0 | 20 | 0 | 0 | 6 |
| Heuristics only | 1.0 | 1.0 | 1.0 | 1.0 | 20 | 0 | 0 | 6 |
| Semantic only | 0.857 | 0.3 | 0.444 | 0.423 | 6 | 1 | 14 | 5 |

**Missed attacks (ensemble):** none

Interpretation: the full ensemble is what ships. Layer rows exist to show each layer's
contribution and that the ensemble is not a single point of failure.

---

## External benchmark (public dataset, untouched by tuning)

Source: deepset/prompt-injections (HuggingFace), vendored Oct 3 2026 — labels by the dataset authors; AgentSentinel tuning never used this data
Samples: 546 · Generated: 2026-10-03 14:06 UTC ·
Layer: full ensemble (active layers only — offline mode uses heuristics + TF-IDF)

| Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| 1.0 | 0.123 | 0.219 | 0.674 | 25 | 0 | 178 | 343 |

**This is the number to trust most.** Unlike the co-designed dev suite and the author-built
held-out set, this data and its labels come from an independent public source and were never
seen during rule tuning. Misses on paraphrased/multilingual/novel attacks are expected for a
rule+TF-IDF system without the LLM judge active; adding `GEMINI_API_KEY` enables the judge
layer, which addresses exactly this tail.
