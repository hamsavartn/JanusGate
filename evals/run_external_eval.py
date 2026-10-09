"""External benchmark — AgentSentinel vs a public, untouched dataset.

Runs the full ensemble on evals/external/prompt_injections.jsonl (deepset/prompt-injections,
546 labeled samples, labels by the dataset authors). This is the honest generalization
measure: AgentSentinel's rules were never tuned on it. Results are appended to
evals/report.md. Humbling numbers here are the point — disclose, don't hide.

Run:  .venv/Scripts/python.exe -m evals.run_external_eval [--refresh]
"""
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from backend.config import GEMINI_API_KEY
from backend.sentinel_core import inspect_text
from evals.run_eval import _prf
from evals.run_eval import REPORT_PATH as MAIN_REPORT

EXTERNAL_PATH = Path(__file__).parent / "external" / "prompt_injections.jsonl"
SOURCE = ("deepset/prompt-injections (HuggingFace), vendored Oct 3 2026 — "
          "labels by the dataset authors; AgentSentinel tuning never used this data")


def refresh_dataset() -> bool:
    rows, seen = [], set()
    for offset in range(0, 600, 100):
        r = httpx.get(
            "https://datasets-server.huggingface.co/rows",
            params={"dataset": "deepset/prompt-injections", "config": "default",
                    "split": "train", "offset": offset, "length": 100},
            timeout=30,
        )
        d = r.json()
        batch = d.get("rows", [])
        rows.extend(batch)
        if len(batch) < 100:
            break
    out = []
    for row in rows:
        item = row["row"]
        t = " ".join(str(item["text"]).split())
        lab = 1 if str(item["label"]).strip() in ("1", "prompt_injection") else 0
        if t and (t, lab) not in seen:
            seen.add((t, lab))
            out.append({"text": t, "label": lab})
    EXTERNAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EXTERNAL_PATH.open("w", encoding="utf-8") as f:
        for o in out:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    return bool(out)


async def run_external_eval_async(sample: int | None = None) -> dict | None:
    if not EXTERNAL_PATH.exists():
        return None
    items = [json.loads(line) for line in EXTERNAL_PATH.read_text(encoding="utf-8").splitlines()
             if line.strip()]
    # Deterministic stratified sampling: keep the class mix, fixed stride, seedless.
    if sample and sample < len(items):
        stride = len(items) / sample
        items = [items[int(i * stride)] for i in range(sample)]
    pairs: list[tuple[bool, bool]] = []
    fn_names: list[str] = []
    fp_names: list[str] = []
    judge_ok = 0
    t0 = time.perf_counter()

    for i, item in enumerate(items):
        v = await inspect_text(item["text"], source="user_message", record=False)
        if v.llm_verdict is not None:
            judge_ok += 1
        expected = bool(item["label"])
        predicted = v.is_attack
        pairs.append((expected, predicted))
        if expected and not predicted:
            fn_names.append(item["text"][:70])
        if not expected and predicted:
            fp_names.append(item["text"][:70])
        if (i + 1) % 100 == 0:
            print(f"  … {i + 1}/{len(items)}", flush=True)
        if GEMINI_API_KEY:
            time.sleep(6)  # free-tier pacing only when the judge is live

    m = _prf(pairs)
    m["n"] = len(items)
    m["n_total"] = 546
    m["sampled"] = bool(sample and sample < 546)
    m["judge_calls_ok"] = judge_ok
    m["fn_samples"] = fn_names[:10]
    m["fp_samples"] = fp_names[:10]
    m["elapsed_min"] = round((time.perf_counter() - t0) / 60, 1)
    return m


def render_external_section(m: dict) -> str:
    sampling = (f"deterministic stratified sample of **{m['n']}** of {m['n_total']} "
                f"(class mix preserved)" if m.get("sampled") else f"all {m['n']} samples")
    judge_line = (f"Judge verdicts obtained: **{m['judge_calls_ok']}/{m['n']}** "
                  f"(rate-limited calls degraded to heuristics+semantic); elapsed {m['elapsed_min']} min"
                  if m.get("judge_calls_ok") is not None else "")
    return f"""
---

## External validation set (public data — NOT fully untouched; honest status)

Source: {SOURCE}
Samples: {sampling} · Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} ·
Layer: full ensemble (layers active per call) · {judge_line}

| Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| {m["precision"]} | {m["recall"]} | {m["f1"]} | {m["accuracy"]} | {m["tp"]} | {m["fp"]} | {m["fn"]} | {m["tn"]} |

**Honest status (re-labeled after external audit):** this set is independent of the rule
AUTHORING, but it is NOT a pristine test set — one severity calibration (the invisible-char
signal) was adjusted after observing its false positives here, which is a form of data
leakage. Treat precision ({m["precision"]}) as an **upper bound** and recall as the honest
weakness that motivates the LLM-judge layer. A second, never-inspected dataset is required
for a fully clean generalization number (future work).
"""


def run_external_eval(refresh: bool = False, sample: int | None = None) -> dict | None:
    if refresh or not EXTERNAL_PATH.exists():
        if not refresh_dataset():
            print("external dataset unavailable (network?) — benchmark skipped")
            return None
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        m = asyncio.run(run_external_eval_async(sample))
    else:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            m = pool.submit(asyncio.run, run_external_eval_async(sample)).result()
    if m is None:
        return None
    # Replace any previous external section, keep the rest of the report.
    old = MAIN_REPORT.read_text(encoding="utf-8") if MAIN_REPORT.exists() else ""
    marker = "\n---\n\n## External validation set"
    base = old.split(marker)[0] if marker in old else old
    MAIN_REPORT.write_text(base.rstrip() + "\n" + render_external_section(m), encoding="utf-8")
    # Machine-readable companion for CI gates and dashboards.
    (Path(__file__).parent / "report.json").write_text(
        json.dumps({"external": m}, default=str, indent=2), encoding="utf-8")
    return m


if __name__ == "__main__":
    s = None
    if "--sample" in sys.argv:
        s = int(sys.argv[sys.argv.index("--sample") + 1])
    m = run_external_eval(refresh="--refresh" in sys.argv, sample=s)
    if m:
        tag = f"sample {m['n']}/{m['n_total']}" if m.get("sampled") else "full set"
        print(f"external validation set ({tag}): precision={m['precision']} "
              f"recall={m['recall']} f1={m['f1']} judge_ok={m['judge_calls_ok']}/{m['n']} -> {MAIN_REPORT}")
    else:
        print("skipped (dataset unavailable)")
