# JanusGate — Held-out evaluation report

Generated: 2026-10-08 16:12 UTC ·
Semantic mode: **tfidf** · LLM judge: **active (Gemini)** ·
Judge verdicts obtained: **0/26** (free-tier rate limits drop the rest; those payloads ran on heuristics+semantic) ·
Latency p50/p95: 1/2 ms

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

| Layer | Precision | Recall (95% CI) | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Full ensemble | 1.0 | 1.0 [1.0–1.0] | 1.0 | 1.0 | 20 | 0 | 0 | 6 |
| Heuristics only | 1.0 | 1.0 [1.0–1.0] | 1.0 | 1.0 | 20 | 0 | 0 | 6 |
| Semantic only | 0.875 | 0.35 [0.15–0.556] | 0.5 | 0.462 | 7 | 1 | 13 | 5 |

**Missed attacks (ensemble):** none

Interpretation: the full ensemble is what ships. Layer rows exist to show each layer's
contribution and that the ensemble is not a single point of failure. Recall CI is a
bootstrap 95% interval (n=20 positives,
seed 42) — small sets carry wide intervals, and that uncertainty is part of the result.

---

## External validation set (public data — NOT fully untouched; honest status)

Source: deepset/prompt-injections (HuggingFace), vendored Oct 3 2026 — labels by the dataset authors; JanusGate tuning never used this data
Samples: deterministic stratified sample of **120** of 546 (class mix preserved) · Generated: 2026-10-08 16:24 UTC ·
Layer: full ensemble (layers active per call) · Judge verdicts obtained: **0/120** (rate-limited calls degraded to heuristics+semantic); elapsed 12.0 min

| Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| 1.0 | 0.136 | 0.24 | 0.683 | 6 | 0 | 38 | 76 |

**Honest status (re-labeled after external audit):** this set is independent of the rule
AUTHORING, but it is NOT a pristine test set — one severity calibration (the invisible-char
signal) was adjusted after observing its false positives here, which is a form of data
leakage. Treat precision (1.0) as an **upper bound** and recall as the honest
weakness that motivates the LLM-judge layer. A second, never-inspected dataset is required
for a fully clean generalization number (future work).
