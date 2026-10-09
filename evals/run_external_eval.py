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
from datetime import datetime, timezone
from pathlib import Path

import httpx

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


async def run_external_eval_async() -> dict | None:
    if not EXTERNAL_PATH.exists():
        return None
    items = [json.loads(line) for line in EXTERNAL_PATH.read_text(encoding="utf-8").splitlines()
             if line.strip()]
    pairs: list[tuple[bool, bool]] = []
    fn_names: list[str] = []
    fp_names: list[str] = []
    for i, item in enumerate(items):
        v = await inspect_text(item["text"], source="user_message", record=False)
        expected = bool(item["label"])
        predicted = v.is_attack
        pairs.append((expected, predicted))
        if expected and not predicted:
            fn_names.append(item["text"][:70])
        if not expected and predicted:
            fp_names.append(item["text"][:70])
        if (i + 1) % 100 == 0:
            print(f"  … {i + 1}/{len(items)}")
    m = _prf(pairs)
    m["n"] = len(items)
    m["fn_samples"] = fn_names[:10]
    m["fp_samples"] = fp_names[:10]
    return m


def render_external_section(m: dict) -> str:
    return f"""
---

## External benchmark (public dataset, untouched by tuning)

Source: {SOURCE}
Samples: {m["n"]} · Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} ·
Layer: full ensemble (active layers only — offline mode uses heuristics + TF-IDF)

| Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| {m["precision"]} | {m["recall"]} | {m["f1"]} | {m["accuracy"]} | {m["tp"]} | {m["fp"]} | {m["fn"]} | {m["tn"]} |

**This is the number to trust most.** Unlike the co-designed dev suite and the author-built
held-out set, this data and its labels come from an independent public source and were never
seen during rule tuning. Misses on paraphrased/multilingual/novel attacks are expected for a
rule+TF-IDF system without the LLM judge active; adding `GEMINI_API_KEY` enables the judge
layer, which addresses exactly this tail.
"""


def run_external_eval(refresh: bool = False) -> dict | None:
    if refresh or not EXTERNAL_PATH.exists():
        if not refresh_dataset():
            print("external dataset unavailable (network?) — benchmark skipped")
            return None
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        m = asyncio.run(run_external_eval_async())
    else:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            m = pool.submit(asyncio.run, run_external_eval_async()).result()
    if m is None:
        return None
    # Replace any previous external section, keep the rest of the report.
    old = MAIN_REPORT.read_text(encoding="utf-8") if MAIN_REPORT.exists() else ""
    marker = "\n---\n\n## External benchmark"
    base = old.split(marker)[0] if marker in old else old
    MAIN_REPORT.write_text(base.rstrip() + "\n" + render_external_section(m), encoding="utf-8")
    return m


if __name__ == "__main__":
    m = run_external_eval(refresh="--refresh" in sys.argv)
    if m:
        print(f"external benchmark: n={m['n']} precision={m['precision']} "
              f"recall={m['recall']} f1={m['f1']} -> {MAIN_REPORT}")
    else:
        print("skipped (dataset unavailable)")
